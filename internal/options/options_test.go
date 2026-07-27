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

package options

import (
	"flag"
	"testing"
	"time"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	o := New()
	if err := o.Validate(); err != nil {
		t.Fatalf("default options must validate: %v", err)
	}

	checks := map[string]bool{
		"scanner component":         o.Component == ComponentScanner,
		"secure metrics":            o.MetricsSecure,
		"leader election":           o.LeaderElect,
		"scan interval":             o.ScanInterval == 30*time.Second,
		"discovery interval":        o.DiscoveryRefreshInterval == 5*time.Minute,
		"scan timeout":              o.ScanTimeout == 2*time.Minute,
		"resource workers":          o.ResourceWorkers == 4,
		"diagnosis workers":         o.DiagnosisWorkers == 8,
		"metadata page size":        o.MetadataPageSize == 500,
		"queued target bound":       o.MaxQueuedTargets == 10_000,
		"remediation attempt bound": o.MaxRemediationAttempts == 5,
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("unexpected default for %s", name)
		}
	}
}

func TestBindParsesComponentAndOverrides(t *testing.T) {
	t.Parallel()

	o := New()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o.Bind(fs)
	if err := fs.Parse([]string{
		"--component=executor",
		"--leader-elect=false",
		"--metrics-secure=false",
		"--scan-interval=45s",
		"--max-remediation-attempts=3",
	}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("parsed options must validate: %v", err)
	}
	if o.Component != ComponentExecutor {
		t.Fatalf("component = %q, want %q", o.Component, ComponentExecutor)
	}
	if o.LeaderElect || o.MetricsSecure {
		t.Fatal("boolean overrides were not applied")
	}
	if o.ScanInterval != 45*time.Second || o.MaxRemediationAttempts != 3 {
		t.Fatal("numeric overrides were not applied")
	}
	if got := o.LeaderElectionID(); got != "executor.safety.exitguard.io" {
		t.Fatalf("leader election ID = %q", got)
	}
}

func TestValidateRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	o := New()
	o.Component = "unknown"
	o.ScanInterval = 0
	o.ResourceWorkers = -1
	o.MaxRemediationAttempts = 0

	if err := o.Validate(); err == nil {
		t.Fatal("Validate() accepted invalid options")
	}
}
