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

// Package options defines validated process configuration shared by both components.
package options

import (
	"errors"
	"flag"
	"fmt"
	"time"
)

// Component selects the least-privilege runtime role registered in the process.
type Component string

const (
	// ComponentScanner runs discovery, diagnosis, and incident persistence.
	ComponentScanner Component = "scanner"
	// ComponentExecutor runs approval-gated remediation.
	ComponentExecutor Component = "executor"
)

// Options contains process and component tuning flags.
type Options struct {
	Component                Component
	MetricsBindAddress       string
	MetricsSecure            bool
	HealthProbeBindAddress   string
	LeaderElect              bool
	ScanInterval             time.Duration
	DiscoveryRefreshInterval time.Duration
	ScanTimeout              time.Duration
	ResourceWorkers          int
	DiagnosisWorkers         int
	MetadataPageSize         int64
	MaxQueuedTargets         int
	MaxRemediationAttempts   int
}

// New returns the fixed v1 defaults.
func New() *Options {
	return &Options{
		Component:                ComponentScanner,
		MetricsBindAddress:       ":8443",
		MetricsSecure:            true,
		HealthProbeBindAddress:   ":8081",
		LeaderElect:              true,
		ScanInterval:             30 * time.Second,
		DiscoveryRefreshInterval: 5 * time.Minute,
		ScanTimeout:              2 * time.Minute,
		ResourceWorkers:          4,
		DiagnosisWorkers:         8,
		MetadataPageSize:         500,
		MaxQueuedTargets:         10_000,
		MaxRemediationAttempts:   5,
	}
}

// Bind registers all flags on fs.
func (o *Options) Bind(fs *flag.FlagSet) {
	fs.Func("component", "runtime component: scanner or executor", func(value string) error {
		o.Component = Component(value)
		return nil
	})
	fs.StringVar(&o.MetricsBindAddress, "metrics-bind-address", o.MetricsBindAddress, "metrics server address")
	fs.BoolVar(&o.MetricsSecure, "metrics-secure", o.MetricsSecure, "serve metrics over HTTPS with delegated authentication and authorization")
	fs.StringVar(&o.HealthProbeBindAddress, "health-probe-bind-address", o.HealthProbeBindAddress, "health probe server address")
	fs.BoolVar(&o.LeaderElect, "leader-elect", o.LeaderElect, "enable leader election")
	fs.DurationVar(&o.ScanInterval, "scan-interval", o.ScanInterval, "interval between scanner cycles")
	fs.DurationVar(&o.DiscoveryRefreshInterval, "discovery-refresh-interval", o.DiscoveryRefreshInterval, "interval between API discovery refreshes")
	fs.DurationVar(&o.ScanTimeout, "scan-timeout", o.ScanTimeout, "whole scanner cycle timeout")
	fs.IntVar(&o.ResourceWorkers, "resource-workers", o.ResourceWorkers, "maximum concurrent resource list operations")
	fs.IntVar(&o.DiagnosisWorkers, "diagnosis-workers", o.DiagnosisWorkers, "maximum concurrent target diagnoses")
	fs.Int64Var(&o.MetadataPageSize, "metadata-page-size", o.MetadataPageSize, "PartialObjectMetadata list page size")
	fs.IntVar(&o.MaxQueuedTargets, "max-queued-targets", o.MaxQueuedTargets, "maximum targets retained in one scan cycle")
	fs.IntVar(&o.MaxRemediationAttempts, "max-remediation-attempts", o.MaxRemediationAttempts, "maximum recorded transient remediation attempts")
}

// Validate rejects unsafe or unusable process configuration.
func (o *Options) Validate() error {
	var errs []error

	if o.Component != ComponentScanner && o.Component != ComponentExecutor {
		errs = append(errs, fmt.Errorf("component must be %q or %q, got %q", ComponentScanner, ComponentExecutor, o.Component))
	}
	if o.MetricsBindAddress == "" {
		errs = append(errs, errors.New("metrics-bind-address must not be empty"))
	}
	if o.HealthProbeBindAddress == "" {
		errs = append(errs, errors.New("health-probe-bind-address must not be empty"))
	}
	if o.ScanInterval <= 0 {
		errs = append(errs, errors.New("scan-interval must be positive"))
	}
	if o.DiscoveryRefreshInterval <= 0 {
		errs = append(errs, errors.New("discovery-refresh-interval must be positive"))
	}
	if o.ScanTimeout <= 0 {
		errs = append(errs, errors.New("scan-timeout must be positive"))
	}
	if o.ResourceWorkers <= 0 {
		errs = append(errs, errors.New("resource-workers must be positive"))
	}
	if o.DiagnosisWorkers <= 0 {
		errs = append(errs, errors.New("diagnosis-workers must be positive"))
	}
	if o.MetadataPageSize <= 0 {
		errs = append(errs, errors.New("metadata-page-size must be positive"))
	}
	if o.MaxQueuedTargets <= 0 {
		errs = append(errs, errors.New("max-queued-targets must be positive"))
	}
	if o.MaxRemediationAttempts <= 0 || o.MaxRemediationAttempts > 5 {
		errs = append(errs, errors.New("max-remediation-attempts must be between 1 and 5"))
	}

	return errors.Join(errs...)
}

// LeaderElectionID returns a component-specific lease identity.
func (o *Options) LeaderElectionID() string {
	return string(o.Component) + ".safety.exitguard.io"
}
