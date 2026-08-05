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

package scanner

import (
	"context"
	"errors"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/metadata"
	"sigs.k8s.io/controller-runtime/pkg/client"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	"github.com/erayack/exitguard/internal/diagnosis"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
)

// cycleRunner executes one complete scanner cycle at the supplied timestamp.
type cycleRunner interface {
	Run(context.Context, time.Time) error
}

// liveCycleRunner owns the scanner dependencies and state that persist across cycles.
type liveCycleRunner struct {
	reader             client.Reader
	writer             client.Client
	metadata           metadata.Interface
	catalog            Catalog
	engine             *diagnosis.Engine
	config             Config
	policyCatalog      []catalogdiscovery.Resource
	policyCompileCache map[policyCompileCacheKey]policyCompileCacheEntry
}

type incidentViewState uint8

const (
	incidentViewUnavailable incidentViewState = iota
	incidentViewFresh
	incidentViewStale
)

type incidentViewChange uint8

const (
	incidentViewUnchanged incidentViewChange = iota
	incidentViewInvalidated
)

type incidentView struct {
	list  *safetyv1alpha1.DeletionIncidentList
	state incidentViewState
}

func (v *incidentView) install(list *safetyv1alpha1.DeletionIncidentList) {
	v.list = list
	if list == nil {
		v.state = incidentViewUnavailable
		return
	}
	v.state = incidentViewFresh
}

func (v *incidentView) apply(change incidentViewChange) {
	if change == incidentViewInvalidated {
		v.state = incidentViewStale
	}
}

func (v *incidentView) metricList() *safetyv1alpha1.DeletionIncidentList {
	if v.state == incidentViewFresh {
		return v.list
	}
	return nil
}

// scanCycle owns all state that is valid for only one runner invocation.
type scanCycle struct {
	runner          *liveCycleRunner
	ctx             context.Context
	now             time.Time
	catalog         catalogdiscovery.Snapshot
	policies        compiledPolicies
	namespaceLabels map[string]map[string]string
	observations    map[types.UID]observation
	coverage        map[schema.GroupResource]resourceCoverage
	incidents       incidentView
	snapshot        diagnosis.Snapshot
	err             error
}

func (r *liveCycleRunner) Run(ctx context.Context, now time.Time) error {
	cycle := scanCycle{runner: r, ctx: ctx, now: now}
	return cycle.run()
}

func (c *scanCycle) run() error {
	if status, ok := c.runner.catalog.(interface{ LastResult() (time.Time, error) }); ok {
		lastSuccess, _ := status.LastResult()
		if lastSuccess.IsZero() {
			return c.degraded(errors.New("discovery catalog has no successful snapshot"), "DiscoveryUnavailable", "discovery has no complete snapshot")
		}
	}

	c.catalog = c.runner.catalog.Snapshot()
	catalogResources.Set(float64(c.catalog.Len()))

	var err error
	c.policies, err = c.runner.compilePolicies(c.ctx, c.catalog, c.now)
	if err != nil {
		return c.degraded(err, "PolicyCompilationFailed", "current policies could not be compiled")
	}

	c.namespaceLabels, err = c.runner.namespaceLabels(c.ctx)
	if err != nil {
		return c.degraded(err, "NamespaceInventoryFailed", "namespace label inventory is incomplete")
	}

	var incidents *safetyv1alpha1.DeletionIncidentList
	c.observations, c.coverage, incidents, err = c.runner.listTargets(c.ctx, c.catalog, c.policies, c.namespaceLabels)
	c.incidents.install(incidents)
	c.addError(err)
	if err != nil && c.ctx.Err() != nil {
		return c.degraded(nil, "ScanTimedOut", "the current scan did not complete")
	}

	c.snapshot = diagnosis.Snapshot{Catalog: c.catalog, NamespaceLabels: c.namespaceLabels}
	if len(c.observations) > 0 {
		c.snapshot, err = c.runner.diagnosisSnapshot(c.ctx, c.catalog, c.namespaceLabels, c.observations)
		if err != nil {
			return c.degraded(err, "SnapshotFailed", "diagnosis snapshot is incomplete")
		}
	}

	diagnosisChange, err := c.runner.diagnoseTargets(c.ctx, c.observations, c.snapshot, c.incidents.list, c.now)
	c.incidents.apply(diagnosisChange)
	c.addError(err)
	if err != nil && c.ctx.Err() != nil {
		return c.degraded(nil, "ScanTimedOut", "the current scan did not complete")
	}

	lifecycleChange, err := c.runner.reconcileLifecycle(c.ctx, c.observations, c.coverage, c.catalog, c.policies, c.incidents.list, c.now)
	c.incidents.apply(lifecycleChange)
	c.addError(err)
	c.finalizeIncidentMetrics(c.ctx)
	return c.err
}

func (c *scanCycle) addError(err error) {
	if err != nil {
		c.err = errors.Join(c.err, err)
	}
}

func (c *scanCycle) degraded(err error, reason, message string) error {
	c.addError(err)
	cleanupCtx, cancel := c.runner.cleanupContext(c.ctx)
	defer cancel()
	degradedErr := c.runner.failActiveIncidentDiagnoses(cleanupCtx, c.now, reason, message)
	c.incidents.apply(incidentViewInvalidated)
	c.finalizeIncidentMetrics(cleanupCtx)
	return errors.Join(c.err, degradedErr)
}

func (c *scanCycle) finalizeIncidentMetrics(ctx context.Context) {
	c.runner.updateIncidentMetrics(ctx, c.incidents.metricList())
}
