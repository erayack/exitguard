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
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
)

type countingReader struct {
	client.Reader
	counters *Counters
}

// NewCountingReader wraps actual controller-runtime reads with operation counters.
func NewCountingReader(delegate client.Reader, counters *Counters) client.Reader {
	return &countingReader{Reader: delegate, counters: counters}
}

func (r *countingReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	r.counters.Record(TypedGet)
	return r.Reader.Get(ctx, key, object, options...)
}

func (r *countingReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	r.counters.Record(listOperation(list))
	return r.Reader.List(ctx, list, options...)
}

type countingClient struct {
	client.Client
	counters *Counters
}

// NewCountingClient wraps actual controller-runtime reads and writes with operation counters.
func NewCountingClient(delegate client.Client, counters *Counters) client.Client {
	return &countingClient{Client: delegate, counters: counters}
}

func (c *countingClient) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	c.counters.Record(TypedGet)
	return c.Client.Get(ctx, key, object, options...)
}

func (c *countingClient) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	c.counters.Record(listOperation(list))
	return c.Client.List(ctx, list, options...)
}

func (c *countingClient) Apply(ctx context.Context, object runtime.ApplyConfiguration, options ...client.ApplyOption) error {
	c.counters.Record(Patch)
	c.counters.Record(Write)
	return c.Client.Apply(ctx, object, options...)
}

func (c *countingClient) Create(ctx context.Context, object client.Object, options ...client.CreateOption) error {
	c.counters.Record(Create)
	c.counters.Record(Write)
	return c.Client.Create(ctx, object, options...)
}

func (c *countingClient) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	c.counters.Record(Delete)
	c.counters.Record(Write)
	return c.Client.Delete(ctx, object, options...)
}

func (c *countingClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	c.counters.Record(Update)
	c.counters.Record(Write)
	return c.Client.Update(ctx, object, options...)
}

func (c *countingClient) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	c.counters.Record(Patch)
	c.counters.Record(Write)
	return c.Client.Patch(ctx, object, patch, options...)
}

func (c *countingClient) DeleteAllOf(ctx context.Context, object client.Object, options ...client.DeleteAllOfOption) error {
	c.counters.Record(Delete)
	c.counters.Record(Write)
	return c.Client.DeleteAllOf(ctx, object, options...)
}

func (c *countingClient) Status() client.StatusWriter {
	return &countingSubresource{SubResourceClient: c.Client.SubResource("status"), counters: c.counters, status: true}
}

func (c *countingClient) SubResource(name string) client.SubResourceClient {
	return &countingSubresource{SubResourceClient: c.Client.SubResource(name), counters: c.counters, status: name == "status"}
}

type countingSubresource struct {
	client.SubResourceClient
	counters *Counters
	status   bool
}

func (s *countingSubresource) Get(ctx context.Context, object, subresource client.Object, options ...client.SubResourceGetOption) error {
	s.counters.Record(TypedGet)
	return s.SubResourceClient.Get(ctx, object, subresource, options...)
}

func (s *countingSubresource) Create(ctx context.Context, object, subresource client.Object, options ...client.SubResourceCreateOption) error {
	s.recordWrite(Create)
	return s.SubResourceClient.Create(ctx, object, subresource, options...)
}

func (s *countingSubresource) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	s.recordWrite(Update)
	return s.SubResourceClient.Update(ctx, object, options...)
}

func (s *countingSubresource) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	s.recordWrite(Patch)
	return s.SubResourceClient.Patch(ctx, object, patch, options...)
}

func (s *countingSubresource) Apply(ctx context.Context, object runtime.ApplyConfiguration, options ...client.SubResourceApplyOption) error {
	s.recordWrite(Patch)
	return s.SubResourceClient.Apply(ctx, object, options...)
}

func (s *countingSubresource) recordWrite(operation Operation) {
	if s.status {
		s.counters.Record(StatusWrite)
	} else {
		s.counters.Record(operation)
	}
	s.counters.Record(Write)
}

func listOperation(list client.ObjectList) Operation {
	switch list.(type) {
	case *safetyv1alpha1.DeletionIncidentList:
		return IncidentList
	case *safetyv1alpha1.TerminationPolicyList:
		return PolicyList
	default:
		return TypedList
	}
}
