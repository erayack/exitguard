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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestHarnessCreatesAndReadsRealObject(t *testing.T) {
	ctx := boundedContext(t)
	created := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      fixtureName(t, "smoke"),
		},
		Data: map[string]string{"source": "envtest"},
	}
	if err := suite.client.Create(ctx, created); err != nil {
		t.Fatalf("create ConfigMap: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = suite.client.Delete(cleanupCtx, created)
	})

	var got corev1.ConfigMap
	if err := suite.client.Get(ctx, ctrlclient.ObjectKeyFromObject(created), &got); err != nil {
		t.Fatalf("get ConfigMap: %v", err)
	}
	if got.Data["source"] != "envtest" || got.UID == "" || got.ResourceVersion == "" {
		t.Fatalf("persisted ConfigMap = %#v, want API-assigned identity and data", got)
	}
}
