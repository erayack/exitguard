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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
)

// TargetReader deliberately uses full objects only for direct diagnosis GETs and metadata for broad lists.
type TargetReader struct {
	dynamic  dynamic.Interface
	metadata metadata.Interface
}

// NewTargetReader adapts Kubernetes clients to the read-only diagnosis interface.
func NewTargetReader(dynamicClient dynamic.Interface, metadataClient metadata.Interface) *TargetReader {
	return &TargetReader{dynamic: dynamicClient, metadata: metadataClient}
}

// Get fetches exactly one target for diagnosis and mutation preconditions.
func (r *TargetReader) Get(ctx context.Context, resource schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error) {
	return r.dynamic.Resource(resource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
}

// ListMetadata performs only a PartialObjectMetadata list.
func (r *TargetReader) ListMetadata(ctx context.Context, resource schema.GroupVersionResource, namespace string, options metav1.ListOptions) (*metav1.PartialObjectMetadataList, error) {
	return r.metadata.Resource(resource).Namespace(namespace).List(ctx, options)
}
