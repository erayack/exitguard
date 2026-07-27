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

// Command manager starts one exitguard runtime component.
package main

import (
	"flag"
	"fmt"
	"os"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sdiscovery "k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/metadata"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	"github.com/erayack/exitguard/internal/diagnosis"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
	"github.com/erayack/exitguard/internal/executor"
	"github.com/erayack/exitguard/internal/options"
	"github.com/erayack/exitguard/internal/scanner"
)

func main() {
	os.Exit(run())
}

func run() int {
	opts := options.New()
	zapOpts := zap.Options{Development: false}
	opts.Bind(flag.CommandLine)
	zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))
	setupLog := ctrl.Log.WithName("setup")

	if err := opts.Validate(); err != nil {
		setupLog.Error(err, "invalid options")
		return 2
	}

	scheme, err := newScheme()
	if err != nil {
		setupLog.Error(err, "register API schemes")
		return 1
	}

	metricsOptions := metricsserver.Options{
		BindAddress:   opts.MetricsBindAddress,
		SecureServing: opts.MetricsSecure,
	}
	if opts.MetricsSecure {
		metricsOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	restConfig, err := ctrl.GetConfig()
	if err != nil {
		setupLog.Error(err, "load Kubernetes REST config")
		return 1
	}
	manager, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsOptions,
		HealthProbeBindAddress: opts.HealthProbeBindAddress,
		LeaderElection:         opts.LeaderElect,
		LeaderElectionID:       opts.LeaderElectionID(),
	})
	if err != nil {
		setupLog.Error(err, "create manager")
		return 1
	}
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "register health check")
		return 1
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "register readiness check")
		return 1
	}
	discoveryClient, err := k8sdiscovery.NewDiscoveryClientForConfig(manager.GetConfig())
	if err != nil {
		setupLog.Error(err, "create discovery client")
		return 1
	}
	catalog := catalogdiscovery.NewCatalog(discoveryClient, opts.DiscoveryRefreshInterval, ctrl.Log.WithName("discovery"))
	if err := manager.Add(catalog); err != nil {
		setupLog.Error(err, "register discovery catalog")
		return 1
	}
	dynamicClient, err := dynamic.NewForConfig(manager.GetConfig())
	if err != nil {
		setupLog.Error(err, "create dynamic client")
		return 1
	}

	switch opts.Component {
	case options.ComponentScanner:
		metadataClient, err := metadata.NewForConfig(manager.GetConfig())
		if err != nil {
			setupLog.Error(err, "create metadata client")
			return 1
		}
		targetReader := scanner.NewTargetReader(dynamicClient, metadataClient)
		coordinator, err := scanner.NewCoordinator(
			manager.GetAPIReader(), manager.GetClient(), metadataClient, catalog,
			diagnosis.NewEngine(targetReader), scanner.Config{
				Interval: opts.ScanInterval, Timeout: opts.ScanTimeout,
				ResourceWorkers: opts.ResourceWorkers, DiagnosisWorkers: opts.DiagnosisWorkers,
				PageSize: opts.MetadataPageSize, MaxTargets: opts.MaxQueuedTargets,
			},
		)
		if err != nil {
			setupLog.Error(err, "create scanner")
			return 1
		}
		if err := manager.Add(coordinator); err != nil {
			setupLog.Error(err, "register scanner")
			return 1
		}
	case options.ComponentExecutor:
		kubeClient, err := kubernetes.NewForConfig(manager.GetConfig())
		if err != nil {
			setupLog.Error(err, "create Kubernetes client")
			return 1
		}
		reconciler, err := executor.NewReconciler(
			manager.GetAPIReader(), manager.GetClient(), dynamicClient, kubeClient, catalog,
			manager.GetEventRecorder("remediation-executor"), opts.MaxRemediationAttempts,
		)
		if err != nil {
			setupLog.Error(err, "create executor")
			return 1
		}
		if err := reconciler.SetupWithManager(manager); err != nil {
			setupLog.Error(err, "register executor")
			return 1
		}
	}

	setupLog.Info("starting component", "component", opts.Component)
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, fmt.Sprintf("run %s component", opts.Component))
		return 1
	}
	return 0
}

func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register Kubernetes scheme: %w", err)
	}
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register apiextensions scheme: %w", err)
	}
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register apiregistration scheme: %w", err)
	}
	if err := safetyv1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register safety API scheme: %w", err)
	}
	return scheme, nil
}
