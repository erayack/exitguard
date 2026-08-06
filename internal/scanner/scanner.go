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

// Package scanner coordinates bounded metadata scans and owns DeletionIncident state.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/util/retry"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	"github.com/erayack/exitguard/internal/diagnosis"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
	policyengine "github.com/erayack/exitguard/internal/policy"
)

const (
	observationRefresh  = 5 * time.Minute
	retentionAnnotation = "safety.exitguard.io/resolved-incident-ttl"
)

var errTargetBound = errors.New("scan target bound exceeded")

// Config contains the bounded scanner controls.
type Config struct {
	Interval         time.Duration
	Timeout          time.Duration
	ResourceWorkers  int
	DiagnosisWorkers int
	PageSize         int64
	MaxTargets       int
}

// Catalog is the discovery snapshot operation used by a scanner cycle.
type Catalog interface {
	Snapshot() catalogdiscovery.Snapshot
}

// Coordinator schedules and serializes scan cycles. It is registered as a leader-elected manager runnable.
type Coordinator struct {
	interval time.Duration
	timeout  time.Duration
	runner   cycleRunner
	now      func() time.Time
	cycleMu  sync.Mutex
}

// NewCoordinator creates a scanner. reader should be the manager API reader so conflict retries are fresh.
func NewCoordinator(reader client.Reader, writer client.Client, metadataClient metadata.Interface, catalog Catalog, engine *diagnosis.Engine, config Config) (*Coordinator, error) {
	if reader == nil || writer == nil || metadataClient == nil || catalog == nil || engine == nil {
		return nil, errors.New("scanner reader, writer, metadata client, catalog, and diagnosis engine are required")
	}
	if config.Interval <= 0 || config.Timeout <= 0 || config.ResourceWorkers <= 0 || config.DiagnosisWorkers <= 0 || config.PageSize <= 0 || config.MaxTargets <= 0 {
		return nil, errors.New("scanner bounds must be positive")
	}
	runner := &liveCycleRunner{reader: reader, writer: writer, metadata: metadataClient, catalog: catalog, engine: engine, config: config}
	return &Coordinator{interval: config.Interval, timeout: config.Timeout, runner: runner, now: time.Now}, nil
}

// NeedLeaderElection prevents more than one active scanner across replicas.
func (*Coordinator) NeedLeaderElection() bool { return true }

// Start scans immediately after manager startup and then at the configured interval.
func (c *Coordinator) Start(ctx context.Context) error {
	c.runTimedCycle(ctx)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.runTimedCycle(ctx)
		}
	}
}

func (c *Coordinator) runTimedCycle(parent context.Context) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	result := "success"
	if err := c.RunCycle(ctx); err != nil {
		result = "error"
		log.FromContext(parent).Error(err, "scanner cycle failed")
	}
	scanCycles.WithLabelValues(result).Inc()
	scanDuration.Observe(time.Since(started).Seconds())
}

// RunCycle executes one non-overlapping scan. A concurrent caller is rejected rather than queued.
func (c *Coordinator) RunCycle(ctx context.Context) error {
	if !c.cycleMu.TryLock() {
		scanCycles.WithLabelValues("overlap_skipped").Inc()
		return errors.New("scanner cycle already running")
	}
	defer c.cycleMu.Unlock()

	return c.runner.Run(ctx, c.now().UTC())
}

type policyCompileCacheKey struct {
	uid  types.UID
	name string
}

type policyCompileCacheEntry struct {
	generation int64
	spec       safetyv1alpha1.TerminationPolicySpec
	compiled   *policyengine.CompiledPolicy
	status     safetyv1alpha1.TerminationPolicyStatus
}

type compiledPolicies struct {
	items []*policyengine.CompiledPolicy
	byUID map[types.UID]*policyengine.CompiledPolicy
}

func (p compiledPolicies) selectWinning(target policyengine.Target) *policyengine.CompiledPolicy {
	for _, candidate := range p.items {
		if candidate.Match(target) {
			return candidate
		}
	}
	return nil
}

func (c *liveCycleRunner) compilePolicies(ctx context.Context, catalog catalogdiscovery.Snapshot, now time.Time) (compiledPolicies, error) {
	var list safetyv1alpha1.TerminationPolicyList
	if err := c.reader.List(ctx, &list); err != nil {
		return compiledPolicies{}, fmt.Errorf("list termination policies: %w", err)
	}
	catalogResources := catalog.Resources()
	cache := c.policyCompileCache
	if !reflect.DeepEqual(c.policyCatalog, catalogResources) {
		cache = nil
	}
	nextCache := make(map[policyCompileCacheKey]policyCompileCacheEntry, len(list.Items))
	result := compiledPolicies{byUID: make(map[types.UID]*policyengine.CompiledPolicy, len(list.Items))}
	readyCount := 0
	for i := range list.Items {
		policy := &list.Items[i]
		key := policyCompileCacheKey{uid: policy.UID, name: policy.Name}
		entry, cached := cache[key]
		if !cached || entry.generation != policy.Generation || !reflect.DeepEqual(entry.spec, policy.Spec) {
			compiled, status := policyengine.Compile(policy, catalog, now)
			entry = policyCompileCacheEntry{generation: policy.Generation, spec: policy.Spec, compiled: compiled, status: status}
		} else {
			validated := metav1.NewTime(now)
			status := entry.status.DeepCopy()
			status.LastValidatedTime = &validated
			for j := range status.Conditions {
				status.Conditions[j].LastTransitionTime = validated
			}
			entry.status = *status
		}
		compiled, status := entry.compiled, *entry.status.DeepCopy()
		nextCache[key] = entry
		if err := c.updatePolicyStatus(ctx, policy, status); err != nil {
			return compiledPolicies{}, err
		}
		result.byUID[compiled.UID()] = compiled
		if compiled.Ready() {
			result.items = append(result.items, compiled)
			readyCount++
		}
	}
	sort.Slice(result.items, func(i, j int) bool {
		if result.items[i].Priority() != result.items[j].Priority() {
			return result.items[i].Priority() > result.items[j].Priority()
		}
		return result.items[i].Name() < result.items[j].Name()
	})
	compiledPoliciesGauge.WithLabelValues("true").Set(float64(readyCount))
	compiledPoliciesGauge.WithLabelValues("false").Set(float64(len(list.Items) - readyCount))
	c.policyCatalog = catalogResources
	c.policyCompileCache = nextCache
	return result, nil
}

func (c *liveCycleRunner) updatePolicyStatus(ctx context.Context, current *safetyv1alpha1.TerminationPolicy, desired safetyv1alpha1.TerminationPolicyStatus) error {
	name := current.Name
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		if current == nil {
			current = &safetyv1alpha1.TerminationPolicy{}
			if err := c.reader.Get(ctx, client.ObjectKey{Name: name}, current); err != nil {
				return err
			}
		}
		desired.Conditions = preserveConditionTransitions(current.Status.Conditions, desired.Conditions)
		if apiequality.Semantic.DeepEqual(current.Status, desired) {
			return nil
		}
		current.Status = desired
		err := c.writer.Status().Update(ctx, current)
		current = nil
		return err
	})
}

func (c *liveCycleRunner) namespaceLabels(ctx context.Context) (map[string]map[string]string, error) {
	labelsByNamespace := make(map[string]map[string]string)
	continueToken := ""
	resource := c.metadata.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"})
	for {
		list, err := resource.List(ctx, metav1.ListOptions{Limit: c.config.PageSize, Continue: continueToken})
		if err != nil {
			return nil, fmt.Errorf("list namespace metadata: %w", err)
		}
		for i := range list.Items {
			labelsByNamespace[list.Items[i].Name] = maps.Clone(list.Items[i].Labels)
		}
		continueToken = list.Continue
		if continueToken == "" {
			return labelsByNamespace, nil
		}
	}
}

func (c *liveCycleRunner) diagnosisSnapshot(ctx context.Context, catalog catalogdiscovery.Snapshot, namespaceLabels map[string]map[string]string, observations map[types.UID]observation) (diagnosis.Snapshot, error) {
	var apiServices apiregistrationv1.APIServiceList
	var mutating admissionv1.MutatingWebhookConfigurationList
	var validating admissionv1.ValidatingWebhookConfigurationList
	for _, list := range []client.ObjectList{&apiServices, &mutating, &validating} {
		if err := c.reader.List(ctx, list); err != nil {
			return diagnosis.Snapshot{}, fmt.Errorf("build diagnosis snapshot: %w", err)
		}
	}
	snapshot := diagnosis.Snapshot{
		Catalog: catalog, APIServices: apiServices.Items, MutatingWebhooks: mutating.Items,
		ValidatingWebhooks: validating.Items, NamespaceLabels: namespaceLabels,
	}
	serviceKeys := make(map[types.NamespacedName]struct{})
	addService := func(reference *admissionv1.ServiceReference) {
		if reference != nil {
			serviceKeys[types.NamespacedName{Namespace: reference.Namespace, Name: reference.Name}] = struct{}{}
		}
	}
	for i := range mutating.Items {
		for j := range mutating.Items[i].Webhooks {
			addService(mutating.Items[i].Webhooks[j].ClientConfig.Service)
		}
	}
	for i := range validating.Items {
		for j := range validating.Items[i].Webhooks {
			addService(validating.Items[i].Webhooks[j].ClientConfig.Service)
		}
	}
	owners := make(map[safetyv1alpha1.ControllerReference]struct{})
	for _, observed := range observations {
		for _, owner := range observed.policy.FinalizerOwners() {
			owners[owner] = struct{}{}
		}
		if observed.target.APIGroup == apiextensionsv1.GroupName && observed.target.Resource == "customresourcedefinitions" {
			var crd apiextensionsv1.CustomResourceDefinition
			if err := c.reader.Get(ctx, client.ObjectKey{Name: observed.target.Name}, &crd); err != nil {
				if !apierrors.IsNotFound(err) {
					return diagnosis.Snapshot{}, fmt.Errorf("get conversion webhook for %s: %w", observed.target.Name, err)
				}
			} else if crd.Spec.Conversion != nil && crd.Spec.Conversion.Webhook != nil && crd.Spec.Conversion.Webhook.ClientConfig.Service != nil {
				service := crd.Spec.Conversion.Webhook.ClientConfig.Service
				serviceKeys[types.NamespacedName{Namespace: service.Namespace, Name: service.Name}] = struct{}{}
			}
		}
	}
	keys := make([]types.NamespacedName, 0, len(serviceKeys))
	for key := range serviceKeys {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	for _, key := range keys {
		var service corev1.Service
		if err := c.reader.Get(ctx, key, &service); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return diagnosis.Snapshot{}, fmt.Errorf("get webhook Service %s: %w", key, err)
		}
		snapshot.Services = append(snapshot.Services, service)
		var endpoints discoveryv1.EndpointSliceList
		if err := c.reader.List(ctx, &endpoints, client.InNamespace(key.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: key.Name}); err != nil {
			return diagnosis.Snapshot{}, fmt.Errorf("list EndpointSlices for Service %s: %w", key, err)
		}
		snapshot.EndpointSlices = append(snapshot.EndpointSlices, endpoints.Items...)
	}
	for owner := range owners {
		key := client.ObjectKey{Namespace: owner.Namespace, Name: owner.Name}
		switch owner.Kind {
		case "Deployment":
			var workload appsv1.Deployment
			if err := c.reader.Get(ctx, key, &workload); err == nil {
				snapshot.Deployments = append(snapshot.Deployments, workload)
			} else if !apierrors.IsNotFound(err) {
				return diagnosis.Snapshot{}, fmt.Errorf("get finalizer owner Deployment %s: %w", key, err)
			}
		case "StatefulSet":
			var workload appsv1.StatefulSet
			if err := c.reader.Get(ctx, key, &workload); err == nil {
				snapshot.StatefulSets = append(snapshot.StatefulSets, workload)
			} else if !apierrors.IsNotFound(err) {
				return diagnosis.Snapshot{}, fmt.Errorf("get finalizer owner StatefulSet %s: %w", key, err)
			}
		case "DaemonSet":
			var workload appsv1.DaemonSet
			if err := c.reader.Get(ctx, key, &workload); err == nil {
				snapshot.DaemonSets = append(snapshot.DaemonSets, workload)
			} else if !apierrors.IsNotFound(err) {
				return diagnosis.Snapshot{}, fmt.Errorf("get finalizer owner DaemonSet %s: %w", key, err)
			}
		}
	}
	return snapshot, nil
}

type observation struct {
	target safetyv1alpha1.TargetReference
	policy *policyengine.CompiledPolicy
	meta   metav1.PartialObjectMetadata
}

type resourceCoverage struct {
	success      bool
	allUIDs      map[types.UID]struct{}
	selectedUIDs map[types.UID]struct{}
	identities   map[string]types.UID
}

type trackedTargets struct {
	uids       map[types.UID]struct{}
	identities map[string]struct{}
}

type targetBudget struct {
	mu       sync.Mutex
	maximum  int
	reserved map[types.UID]struct{}
}

func (b *targetBudget) reserve(uid types.UID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.reserved[uid]; exists {
		return true
	}
	if len(b.reserved) >= b.maximum {
		return false
	}
	b.reserved[uid] = struct{}{}
	return true
}

func (c *liveCycleRunner) resourcesToScan(ctx context.Context, catalog catalogdiscovery.Snapshot, policies compiledPolicies) ([]catalogdiscovery.Resource, map[schema.GroupResource]trackedTargets, *safetyv1alpha1.DeletionIncidentList, error) {
	selected := make(map[schema.GroupResource]catalogdiscovery.Resource)
	for _, policy := range policies.items {
		for _, groupResource := range policy.ResolvedGroupResources() {
			if resource, found := catalog.Resolve(groupResource); found {
				selected[groupResource] = resource
			}
		}
	}
	var incidents safetyv1alpha1.DeletionIncidentList
	if err := c.reader.List(ctx, &incidents); err != nil {
		return nil, nil, nil, fmt.Errorf("list incidents for scan scope: %w", err)
	}
	tracked := make(map[schema.GroupResource]trackedTargets)
	for i := range incidents.Items {
		incident := &incidents.Items[i]
		if incident.Status.Phase == safetyv1alpha1.IncidentPhaseResolved {
			continue
		}
		groupResource := schema.GroupResource{Group: incident.Spec.Target.APIGroup, Resource: incident.Spec.Target.Resource}
		resource, found := catalog.Resolve(groupResource)
		if !found {
			continue
		}
		selected[groupResource] = resource
		entry := tracked[groupResource]
		if entry.uids == nil {
			entry.uids = make(map[types.UID]struct{})
		}
		entry.uids[incident.Spec.Target.UID] = struct{}{}
		if entry.identities == nil {
			entry.identities = make(map[string]struct{})
		}
		entry.identities[objectIdentity(incident.Spec.Target.Namespace, incident.Spec.Target.Name)] = struct{}{}
		tracked[groupResource] = entry
	}
	resources := make([]catalogdiscovery.Resource, 0, len(selected))
	for _, resource := range selected {
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].GroupResource.String() < resources[j].GroupResource.String() })
	return resources, tracked, &incidents, nil
}

func (c *liveCycleRunner) listTargets(ctx context.Context, catalog catalogdiscovery.Snapshot, policies compiledPolicies, namespaceLabels map[string]map[string]string) (map[types.UID]observation, map[schema.GroupResource]resourceCoverage, *safetyv1alpha1.DeletionIncidentList, error) {
	resources, tracked, incidents, err := c.resourcesToScan(ctx, catalog, policies)
	if err != nil {
		return nil, nil, nil, err
	}
	budget := &targetBudget{maximum: c.config.MaxTargets, reserved: make(map[types.UID]struct{})}
	jobs := make(chan catalogdiscovery.Resource)
	type result struct {
		resource catalogdiscovery.Resource
		items    []metav1.PartialObjectMetadata
		err      error
	}
	results := make(chan result, len(resources))
	var workers sync.WaitGroup
	for range c.config.ResourceWorkers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for resource := range jobs {
				items, version, err := c.listResource(ctx, resource, policies, namespaceLabels, tracked[resource.GroupResource], budget)
				resource.PreferredVersion = version
				results <- result{resource: resource, items: items, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, resource := range resources {
			select {
			case jobs <- resource:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()

	observations := make(map[types.UID]observation)
	coverage := make(map[schema.GroupResource]resourceCoverage, len(resources))
	var errs []error
	truncated := false
	for listed := range results {
		state := resourceCoverage{success: listed.err == nil, allUIDs: map[types.UID]struct{}{}, selectedUIDs: map[types.UID]struct{}{}, identities: map[string]types.UID{}}
		if listed.err != nil {
			resourceLists.WithLabelValues(listResult(listed.err)).Inc()
			errs = append(errs, fmt.Errorf("list %s: %w", listed.resource.GroupResource, listed.err))
			if !errors.Is(listed.err, errTargetBound) {
				coverage[listed.resource.GroupResource] = state
				continue
			}
			truncated = true
		} else {
			resourceLists.WithLabelValues("success").Inc()
		}
		for i := range listed.items {
			item := &listed.items[i]
			state.allUIDs[item.UID] = struct{}{}
			state.identities[objectIdentity(item.Namespace, item.Name)] = item.UID
			target := policyengine.Target{GroupResource: listed.resource.GroupResource, Namespaced: listed.resource.PreferredVersion.Namespaced, Namespace: item.Namespace, Labels: item.Labels, NamespaceLabels: namespaceLabels[item.Namespace]}
			winner := policies.selectWinning(target)
			if winner == nil {
				continue
			}
			state.selectedUIDs[item.UID] = struct{}{}
			if item.DeletionTimestamp == nil {
				continue
			}
			if _, exists := observations[item.UID]; exists {
				continue
			}
			observations[item.UID] = observation{policy: winner, meta: *item, target: safetyv1alpha1.TargetReference{
				APIGroup: listed.resource.GroupResource.Group, Version: listed.resource.PreferredVersion.Version,
				Resource: listed.resource.GroupResource.Resource, Kind: listed.resource.PreferredVersion.Kind,
				Namespace: item.Namespace, Name: item.Name, UID: item.UID,
			}}
		}
		coverage[listed.resource.GroupResource] = state
	}
	if truncated {
		for gr, state := range coverage {
			state.success = false
			coverage[gr] = state
		}
		errs = append(errs, fmt.Errorf("scan target bound %d exceeded", c.config.MaxTargets))
	}
	return observations, coverage, incidents, errors.Join(errs...)
}

func (c *liveCycleRunner) listResource(ctx context.Context, resource catalogdiscovery.Resource, policies compiledPolicies, namespaceLabels map[string]map[string]string, tracked trackedTargets, budget *targetBudget) ([]metav1.PartialObjectMetadata, catalogdiscovery.Version, error) {
	var lastUnavailable error
	for _, version := range resource.OrderedVersions(resource.PreferredVersion.Version) {
		items, err := c.listResourceVersion(ctx, resource, version, policies, namespaceLabels, tracked, budget)
		if err == nil || errors.Is(err, errTargetBound) {
			return items, version, err
		}
		if !apierrors.IsNotFound(err) && !apierrors.IsGone(err) {
			return nil, version, err
		}
		lastUnavailable = err
	}
	return nil, resource.PreferredVersion, lastUnavailable
}

func (c *liveCycleRunner) listResourceVersion(ctx context.Context, resource catalogdiscovery.Resource, version catalogdiscovery.Version, policies compiledPolicies, namespaceLabels map[string]map[string]string, tracked trackedTargets, budget *targetBudget) ([]metav1.PartialObjectMetadata, error) {
	gvr := resource.GroupResource.WithVersion(version.Version)
	var retained []metav1.PartialObjectMetadata
	continueToken := ""
	for {
		list, err := c.metadata.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{Limit: c.config.PageSize, Continue: continueToken})
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			item := &list.Items[i]
			target := policyengine.Target{GroupResource: resource.GroupResource, Namespaced: version.Namespaced, Namespace: item.Namespace, Labels: item.Labels, NamespaceLabels: namespaceLabels[item.Namespace]}
			selectedDeleting := item.DeletionTimestamp != nil && policies.selectWinning(target) != nil
			_, trackedUID := tracked.uids[item.UID]
			_, trackedIdentity := tracked.identities[objectIdentity(item.Namespace, item.Name)]
			if !selectedDeleting && !trackedUID && !trackedIdentity {
				continue
			}
			if selectedDeleting && !budget.reserve(item.UID) {
				return retained, errTargetBound
			}
			retained = append(retained, *item)
		}
		continueToken = list.Continue
		if continueToken == "" {
			return retained, nil
		}
	}
}

func (c *liveCycleRunner) diagnoseTargets(ctx context.Context, observations map[types.UID]observation, snapshot diagnosis.Snapshot, incidents *safetyv1alpha1.DeletionIncidentList, now time.Time) (incidentViewChange, error) {
	knownIncidents := make(map[types.UID]*safetyv1alpha1.DeletionIncident)
	if incidents != nil {
		knownIncidents = make(map[types.UID]*safetyv1alpha1.DeletionIncident, len(incidents.Items))
		for i := range incidents.Items {
			incident := &incidents.Items[i]
			knownIncidents[incident.Spec.Target.UID] = incident
		}
	}
	jobs := make(chan observation)
	errs := make(chan error, len(observations))
	// Status refreshes are frequent, but only creates and phase transitions can
	// make the incident list stale for the phase gauges.
	var metricsDirty atomic.Bool
	var workers sync.WaitGroup
	for range c.config.DiagnosisWorkers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for observed := range jobs {
				result, diagnoseErr := c.engine.Diagnose(ctx, diagnosis.Request{Target: observed.target, Policy: observed.policy, Snapshot: snapshot, Now: now})
				if diagnoseErr != nil {
					thresholdElapsed := observed.meta.DeletionTimestamp != nil && !now.Before(observed.meta.DeletionTimestamp.Add(observed.policy.Settings().TerminationAge))
					result = diagnosis.Result{TargetFound: true, UIDMatches: true, ThresholdElapsed: thresholdElapsed}
				}
				persistErr := c.persistDiagnosis(ctx, observed, result, knownIncidents[observed.target.UID], &metricsDirty, now)
				err := errors.Join(diagnoseErr, persistErr)
				if err != nil {
					diagnoses.WithLabelValues("error").Inc()
					errs <- fmt.Errorf("diagnose %s: %w", incidentName(observed.target.UID), err)
				} else {
					diagnoses.WithLabelValues("success").Inc()
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, uid := range sortedUIDs(observations) {
			select {
			case jobs <- observations[uid]:
			case <-ctx.Done():
				return
			}
		}
	}()
	workers.Wait()
	close(errs)
	var collected []error
	for err := range errs {
		collected = append(collected, err)
	}
	change := incidentViewUnchanged
	if metricsDirty.Load() {
		change = incidentViewInvalidated
	}
	return change, errors.Join(collected...)
}

func (c *liveCycleRunner) persistDiagnosis(ctx context.Context, observed observation, result diagnosis.Result, existing *safetyv1alpha1.DeletionIncident, metricsDirty *atomic.Bool, now time.Time) error {
	name := incidentName(observed.target.UID)
	var err error
	if existing == nil {
		existing = &safetyv1alpha1.DeletionIncident{}
		err = c.reader.Get(ctx, client.ObjectKey{Name: name}, existing)
		if err == nil {
			// A concurrent create was absent from the scan-scope list.
			metricsDirty.Store(true)
		}
	}
	switch {
	case apierrors.IsNotFound(err):
		if !result.TargetFound || !result.UIDMatches || !result.ThresholdElapsed {
			return nil
		}
		incident := &safetyv1alpha1.DeletionIncident{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{retentionAnnotation: observed.policy.Settings().ResolvedIncidentTTL.String()}}, Spec: safetyv1alpha1.DeletionIncidentSpec{Target: observed.target, FirstObservedTime: metav1.NewTime(now)}}
		if err := c.writer.Create(ctx, incident); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
		metricsDirty.Store(true)
	case err != nil:
		return err
	case existing.Spec.Target.UID != observed.target.UID:
		return fmt.Errorf("incident %s belongs to different target UID", name)
	case !result.TargetFound:
		metricsDirty.Store(true)
		return c.resolveIncident(ctx, name, "TargetAbsent", now)
	case !result.UIDMatches:
		metricsDirty.Store(true)
		return c.resolveIncident(ctx, name, "TargetReplaced", now)
	}
	var current *safetyv1alpha1.DeletionIncident
	if err == nil {
		current = existing
	}
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		if current == nil {
			current = &safetyv1alpha1.DeletionIncident{}
			if err := c.reader.Get(ctx, client.ObjectKey{Name: name}, current); err != nil {
				return err
			}
		}
		retention := observed.policy.Settings().ResolvedIncidentTTL.String()
		if current.Annotations[retentionAnnotation] != retention {
			base := current.DeepCopy()
			if current.Annotations == nil {
				current.Annotations = make(map[string]string)
			}
			current.Annotations[retentionAnnotation] = retention
			if err := c.writer.Patch(ctx, current, client.MergeFrom(base)); err != nil {
				current = nil
				return err
			}
		}
		desired := current.Status.DeepCopy()
		desired.ActivePolicyRef = &safetyv1alpha1.PolicyReference{Name: observed.policy.Name(), UID: observed.policy.UID(), Generation: observed.policy.Generation()}
		desired.DeletionTimestamp = observed.meta.DeletionTimestamp.DeepCopy()
		desired.TargetSnapshot = result.TargetSnapshot
		desired.Findings = result.Findings
		actionsChanged := !reflect.DeepEqual(current.Status.RecommendedActions, result.Actions)
		desired.RecommendedActions = result.Actions
		if result.DiagnosisComplete && len(result.Actions) > 0 {
			refreshLead := max(c.config.Interval, c.config.Timeout)
			if actionsChanged || desired.ActionEvidenceTime == nil || desired.ActionEvidenceExpiresTime == nil || desired.ActionEvidenceExpiresTime.Sub(now) <= refreshLead {
				observedAt := metav1.NewTime(now)
				expiresAt := metav1.NewTime(now.Add(c.config.Timeout + 2*c.config.Interval))
				desired.ActionEvidenceTime = &observedAt
				desired.ActionEvidenceExpiresTime = &expiresAt
			}
		} else {
			desired.ActionEvidenceTime = nil
			desired.ActionEvidenceExpiresTime = nil
		}
		desired.ResolvedTime = nil
		desired.ResolutionReason = ""
		if result.DiagnosisComplete {
			desired.Phase = safetyv1alpha1.IncidentPhaseActive
		} else {
			desired.Phase = safetyv1alpha1.IncidentPhaseDiagnosisFailed
		}
		desired.Conditions = preserveConditionTransitions(current.Status.Conditions, diagnosisConditions(result, now))
		if current.Status.LastObservedTime == nil || now.Sub(current.Status.LastObservedTime.Time) >= observationRefresh {
			t := metav1.NewTime(now)
			desired.LastObservedTime = &t
		}
		if apiequality.Semantic.DeepEqual(current.Status, *desired) {
			return nil
		}
		if current.Status.Phase != desired.Phase {
			metricsDirty.Store(true)
		}
		current.Status = *desired
		err := c.writer.Status().Update(ctx, current)
		current = nil
		return err
	})
	if apierrors.IsRequestEntityTooLargeError(err) {
		metricsDirty.Store(true)
		fallbackErr := c.failIncidentDiagnosis(ctx, name, now, "EvidenceTooLarge", "diagnostic evidence exceeded the Kubernetes object size limit")
		return errors.Join(err, fallbackErr)
	}
	return err
}

func (c *liveCycleRunner) reconcileLifecycle(ctx context.Context, observations map[types.UID]observation, coverage map[schema.GroupResource]resourceCoverage, catalog catalogdiscovery.Snapshot, policies compiledPolicies, incidents *safetyv1alpha1.DeletionIncidentList, now time.Time) (incidentViewChange, error) {
	if incidents == nil {
		incidents = &safetyv1alpha1.DeletionIncidentList{}
		if err := c.reader.List(ctx, incidents); err != nil {
			return incidentViewUnchanged, fmt.Errorf("list incidents: %w", err)
		}
	}
	change := incidentViewUnchanged
	var errs []error
	for i := range incidents.Items {
		incident := &incidents.Items[i]
		if incident.Status.Phase == safetyv1alpha1.IncidentPhaseResolved {
			retention, known := incidentRetention(incident, policies)
			if known && incident.Status.ResolvedTime != nil && !now.Before(incident.Status.ResolvedTime.Add(retention)) {
				change = incidentViewInvalidated
				if err := c.writer.Delete(ctx, incident); err != nil && !apierrors.IsNotFound(err) {
					errs = append(errs, err)
				}
			}
			continue
		}
		if _, processed := observations[incident.Spec.Target.UID]; processed {
			continue
		}
		gr := schema.GroupResource{Group: incident.Spec.Target.APIGroup, Resource: incident.Spec.Target.Resource}
		if _, exists := catalog.Resolve(gr); !exists {
			change = incidentViewInvalidated
			if err := c.resolveIncident(ctx, incident.Name, "ResourceTypeRemoved", now); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		state, covered := coverage[gr]
		if !covered {
			continue
		}
		if !state.success {
			change = incidentViewInvalidated
			if err := c.failIncidentDiagnosis(ctx, incident.Name, now, "ResourceListFailed", "resource coverage is incomplete"); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if _, exists := state.allUIDs[incident.Spec.Target.UID]; !exists {
			reason := "TargetAbsent"
			if currentUID, sameName := state.identities[objectIdentity(incident.Spec.Target.Namespace, incident.Spec.Target.Name)]; sameName && currentUID != incident.Spec.Target.UID {
				reason = "TargetReplaced"
			}
			change = incidentViewInvalidated
			if err := c.resolveIncident(ctx, incident.Name, reason, now); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if _, selected := state.selectedUIDs[incident.Spec.Target.UID]; !selected {
			change = incidentViewInvalidated
			if err := c.resolveIncident(ctx, incident.Name, "PolicyNoLongerMatches", now); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		// A successfully covered, selected target omitted from work is no longer deleting.
		change = incidentViewInvalidated
		if err := c.resolveIncident(ctx, incident.Name, "TargetNoLongerDeleting", now); err != nil {
			errs = append(errs, err)
		}
	}
	return change, errors.Join(errs...)
}

func (c *liveCycleRunner) cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx.Err() == nil {
		return ctx, func() {}
	}
	cleanupTimeout := min(c.config.Timeout, 10*time.Second)
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

func (c *liveCycleRunner) failActiveIncidentDiagnoses(ctx context.Context, now time.Time, reason, message string) error {
	writeCtx, cancel := c.cleanupContext(ctx)
	defer cancel()
	var incidents safetyv1alpha1.DeletionIncidentList
	if err := c.reader.List(writeCtx, &incidents); err != nil {
		return fmt.Errorf("list incidents to block stale remediation: %w", err)
	}
	var errs []error
	for i := range incidents.Items {
		if incidents.Items[i].Status.Phase == safetyv1alpha1.IncidentPhaseResolved {
			continue
		}
		if err := c.failIncidentDiagnosis(writeCtx, incidents.Items[i].Name, now, reason, message); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *liveCycleRunner) failIncidentDiagnosis(ctx context.Context, name string, now time.Time, reason, message string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current safetyv1alpha1.DeletionIncident
		if err := c.reader.Get(ctx, client.ObjectKey{Name: name}, &current); err != nil {
			return client.IgnoreNotFound(err)
		}
		if current.Status.Phase == safetyv1alpha1.IncidentPhaseResolved {
			return nil
		}
		before := current.Status.DeepCopy()
		transitionTime := metav1.NewTime(now)
		current.Status.Phase = safetyv1alpha1.IncidentPhaseDiagnosisFailed
		current.Status.TargetSnapshot = safetyv1alpha1.TargetSnapshot{}
		current.Status.Findings = nil
		current.Status.RecommendedActions = nil
		current.Status.ActionEvidenceTime = nil
		current.Status.ActionEvidenceExpiresTime = nil
		current.Status.Conditions = preserveConditionTransitions(current.Status.Conditions, []metav1.Condition{
			{Type: "DiagnosisComplete", Status: metav1.ConditionFalse, Reason: reason, Message: message, LastTransitionTime: transitionTime, ObservedGeneration: current.Generation},
			{Type: "TargetVisible", Status: metav1.ConditionUnknown, Reason: reason, Message: "target visibility is unknown because current evidence is incomplete", LastTransitionTime: transitionTime, ObservedGeneration: current.Generation},
		})
		if apiequality.Semantic.DeepEqual(*before, current.Status) {
			return nil
		}
		return c.writer.Status().Update(ctx, &current)
	})
}

func (c *liveCycleRunner) resolveIncident(ctx context.Context, name, reason string, now time.Time) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current safetyv1alpha1.DeletionIncident
		if err := c.reader.Get(ctx, client.ObjectKey{Name: name}, &current); err != nil {
			return client.IgnoreNotFound(err)
		}
		if current.Status.Phase == safetyv1alpha1.IncidentPhaseResolved {
			return nil
		}
		t := metav1.NewTime(now)
		current.Status.Phase = safetyv1alpha1.IncidentPhaseResolved
		current.Status.ResolvedTime = &t
		current.Status.ResolutionReason = reason
		// Retain the last action snapshot so an executor can audit a mutation that
		// succeeded immediately before incident resolution.
		current.Status.Conditions = []metav1.Condition{{Type: "TargetVisible", Status: metav1.ConditionFalse, Reason: reason, Message: "target is no longer an active monitored deletion", LastTransitionTime: t, ObservedGeneration: current.Generation}}
		return c.writer.Status().Update(ctx, &current)
	})
}

func (c *liveCycleRunner) updateIncidentMetrics(ctx context.Context, incidents *safetyv1alpha1.DeletionIncidentList) {
	if incidents == nil {
		incidents = &safetyv1alpha1.DeletionIncidentList{}
		if err := c.reader.List(ctx, incidents); err != nil {
			return
		}
	}
	counts := map[safetyv1alpha1.IncidentPhase]int{}
	for i := range incidents.Items {
		counts[incidents.Items[i].Status.Phase]++
	}
	for _, phase := range []safetyv1alpha1.IncidentPhase{safetyv1alpha1.IncidentPhaseActive, safetyv1alpha1.IncidentPhaseDiagnosisFailed, safetyv1alpha1.IncidentPhaseResolved} {
		activeIncidents.WithLabelValues(string(phase)).Set(float64(counts[phase]))
	}
}

func preserveConditionTransitions(current, desired []metav1.Condition) []metav1.Condition {
	byType := make(map[string]metav1.Condition, len(current))
	for _, condition := range current {
		byType[condition.Type] = condition
	}
	for i := range desired {
		previous, found := byType[desired[i].Type]
		if found && previous.Status == desired[i].Status {
			desired[i].LastTransitionTime = previous.LastTransitionTime
		}
	}
	return desired
}

func diagnosisConditions(result diagnosis.Result, now time.Time) []metav1.Condition {
	t := metav1.NewTime(now)
	visibleStatus, visibleReason := metav1.ConditionTrue, "TargetObserved"
	if !result.TargetFound {
		visibleStatus, visibleReason = metav1.ConditionFalse, "TargetAbsent"
	} else if !result.UIDMatches {
		visibleStatus, visibleReason = metav1.ConditionFalse, "TargetReplaced"
	}
	completeStatus, completeReason := metav1.ConditionTrue, "DiagnosisComplete"
	if !result.DiagnosisComplete {
		completeStatus, completeReason = metav1.ConditionFalse, "DiagnosisIncomplete"
	}
	return []metav1.Condition{
		{Type: "DiagnosisComplete", Status: completeStatus, Reason: completeReason, LastTransitionTime: t},
		{Type: "TargetVisible", Status: visibleStatus, Reason: visibleReason, LastTransitionTime: t},
	}
}

func incidentName(uid types.UID) string            { return "deletion-" + string(uid) }
func objectIdentity(namespace, name string) string { return namespace + "\x00" + name }
func incidentRetention(incident *safetyv1alpha1.DeletionIncident, policies compiledPolicies) (time.Duration, bool) {
	if policy := policies.byUID[policyUID(incident.Status.ActivePolicyRef)]; policy != nil && policy.Settings().ResolvedIncidentTTL > 0 {
		return policy.Settings().ResolvedIncidentTTL, true
	}
	if value := incident.Annotations[retentionAnnotation]; value != "" {
		parsed, err := time.ParseDuration(value)
		if err == nil && parsed > 0 {
			return parsed, true
		}
	}
	return 0, false
}
func policyUID(ref *safetyv1alpha1.PolicyReference) types.UID {
	if ref == nil {
		return ""
	}
	return ref.UID
}
func listResult(err error) string {
	switch {
	case apierrors.IsForbidden(err):
		return "forbidden"
	case apierrors.IsNotFound(err) || apierrors.IsMethodNotSupported(err):
		return "unsupported"
	default:
		return "error"
	}
}

// Keep map iteration from affecting tests that inspect work order.
func sortedUIDs(items map[types.UID]observation) []types.UID {
	result := make([]types.UID, 0, len(items))
	for uid := range items {
		result = append(result, uid)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
