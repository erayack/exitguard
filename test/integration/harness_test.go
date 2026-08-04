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

//go:build integration

package integration

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/events"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	"github.com/erayack/exitguard/internal/diagnosis"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
	"github.com/erayack/exitguard/internal/executor"
	"github.com/erayack/exitguard/internal/scanner"
)

const operationTimeout = 30 * time.Second

var suite integrationSuite

type integrationSuite struct {
	root        string
	environment *envtest.Environment
	client      ctrlclient.Client
	dynamic     dynamic.Interface
	metadata    metadata.Interface
	kubernetes  kubernetes.Interface
	discovery   discovery.DiscoveryInterface
	catalog     *catalogdiscovery.Catalog
}

func TestMain(m *testing.M) {
	code := 1
	if err := suite.start(); err != nil {
		fmt.Fprintf(os.Stderr, "integration harness startup failed: %v\n", err)
	} else {
		code = m.Run()
		if err := suite.stop(); err != nil {
			fmt.Fprintf(os.Stderr, "integration harness shutdown failed: %v\n", err)
			code = 1
		}
	}
	os.Exit(code)
}

func (s *integrationSuite) start() error {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		return fmt.Errorf("KUBEBUILDER_ASSETS is unset; run make test-integration")
	}
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	s.root = root
	s.environment = &envtest.Environment{
		BinaryAssetsDirectory:    assets,
		CRDDirectoryPaths:        []string{filepath.Join(root, "config", "crd", "bases")},
		ErrorIfCRDPathMissing:    true,
		ControlPlaneStartTimeout: time.Minute,
		ControlPlaneStopTimeout:  time.Minute,
	}
	config, err := s.environment.Start()
	if err != nil {
		return fmt.Errorf("start envtest control plane: %w", err)
	}
	started := true
	defer func() {
		if started {
			_ = s.environment.Stop()
		}
	}()

	scheme := k8sruntime.NewScheme()
	registrations := []func(*k8sruntime.Scheme) error{
		clientgoscheme.AddToScheme,
		safetyv1alpha1.AddToScheme,
		apiextensionsv1.AddToScheme,
		apiregistrationv1.AddToScheme,
		admissionv1.AddToScheme,
		appsv1.AddToScheme,
		corev1.AddToScheme,
		discoveryv1.AddToScheme,
	}
	for _, register := range registrations {
		if err := register(scheme); err != nil {
			return fmt.Errorf("register integration scheme: %w", err)
		}
	}
	if s.client, err = ctrlclient.New(config, ctrlclient.Options{Scheme: scheme}); err != nil {
		return fmt.Errorf("create controller-runtime client: %w", err)
	}
	if s.dynamic, err = dynamic.NewForConfig(config); err != nil {
		return fmt.Errorf("create dynamic client: %w", err)
	}
	if s.metadata, err = metadata.NewForConfig(config); err != nil {
		return fmt.Errorf("create metadata client: %w", err)
	}
	if s.kubernetes, err = kubernetes.NewForConfig(config); err != nil {
		return fmt.Errorf("create Kubernetes client: %w", err)
	}
	if s.discovery, err = discovery.NewDiscoveryClientForConfig(config); err != nil {
		return fmt.Errorf("create discovery client: %w", err)
	}
	s.catalog = catalogdiscovery.NewCatalog(s.discovery, time.Hour, logr.Discard())
	if err := s.catalog.Refresh(); err != nil {
		return fmt.Errorf("refresh discovery catalog: %w", err)
	}
	started = false
	return nil
}

func (s *integrationSuite) stop() error {
	if s.environment == nil {
		return nil
	}
	if err := s.environment.Stop(); err != nil {
		return fmt.Errorf("stop envtest control plane: %w", err)
	}
	return nil
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("resolve integration harness source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("resolve repository root %q: %w", root, err)
	}
	return root, nil
}

func fixtureName(t *testing.T, prefix string) string {
	t.Helper()
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(t.Name()))
	base := strings.ToLower(strings.NewReplacer("/", "-", "_", "-").Replace(t.Name()))
	base = strings.Trim(base, "-")
	if len(base) > 32 {
		base = base[:32]
	}
	return fmt.Sprintf("%s-%s-%08x", prefix, base, hash.Sum32())
}

func boundedContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	t.Cleanup(cancel)
	return ctx
}

func poll(t *testing.T, check func(context.Context) (bool, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		done, err := check(ctx)
		if err != nil {
			t.Fatalf("poll integration state: %v", err)
		}
		if done {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("poll integration state: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func newScanner(t *testing.T) *scanner.Coordinator {
	t.Helper()
	targetReader := scanner.NewTargetReader(suite.dynamic, suite.metadata)
	coordinator, err := scanner.NewCoordinator(
		suite.client, suite.client, suite.metadata, suite.catalog,
		diagnosis.NewEngine(targetReader), scanner.Config{
			Interval: time.Minute, Timeout: operationTimeout,
			ResourceWorkers: 2, DiagnosisWorkers: 2,
			PageSize: 50, MaxTargets: 100,
		},
	)
	if err != nil {
		t.Fatalf("construct scanner: %v", err)
	}
	return coordinator
}

func newExecutor(t *testing.T) *executor.Reconciler {
	t.Helper()
	reconciler, err := executor.NewReconciler(
		suite.client, suite.client, suite.dynamic, suite.kubernetes,
		suite.catalog, events.NewFakeRecorder(10), 5,
	)
	if err != nil {
		t.Fatalf("construct executor: %v", err)
	}
	return reconciler
}
