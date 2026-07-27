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

// Package diagnosis provides read-only deletion-blocker analysis.
package diagnosis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	policyengine "github.com/erayack/exitguard/internal/policy"
)

const (
	maxPersistedEvidenceBytes = 384 * 1024
	maxPersistedFindings      = 512
	maxPersistedActions       = 256
)

var (
	namespaceResource = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	crdResource       = schema.GroupVersionResource{Group: apiextensionsv1.GroupName, Version: "v1", Resource: "customresourcedefinitions"}
)

// Diagnose confirms target identity before dispatching to the specialized analyzers.
func (e *Engine) Diagnose(ctx context.Context, request Request) (Result, error) {
	if e == nil || e.reader == nil {
		return Result{}, errors.New("diagnosis reader is required")
	}
	if request.Policy == nil {
		return Result{}, errors.New("compiled policy is required")
	}
	if !request.Policy.Ready() {
		return Result{}, errors.New("compiled policy must be ready")
	}
	if request.Now.IsZero() {
		return Result{}, errors.New("diagnosis time is required")
	}

	groupResource := schema.GroupResource{Group: request.Target.APIGroup, Resource: request.Target.Resource}
	target, gvr, err := e.getTarget(ctx, request)
	if apierrors.IsNotFound(err) || apierrors.IsGone(err) {
		return Result{DiagnosisComplete: true}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("get diagnosis target: %w", err)
	}
	request.Target.Version = gvr.Version
	if resource, found := request.Snapshot.Catalog.Resolve(groupResource); found {
		for _, version := range resource.OrderedVersions(gvr.Version) {
			if version.Version == gvr.Version {
				request.Target.Kind = version.Kind
				break
			}
		}
	}

	result := Result{TargetFound: true, DiagnosisComplete: true}
	if target.GetUID() != request.Target.UID {
		return result, nil
	}
	result.UIDMatches = true
	result.TargetSnapshot = safetyv1alpha1.TargetSnapshot{
		ResourceVersion:    target.GetResourceVersion(),
		MetadataFinalizers: sortedCopy(target.GetFinalizers()),
	}
	deletionTimestamp := target.GetDeletionTimestamp()
	if deletionTimestamp == nil {
		return result, nil
	}
	result.ThresholdElapsed = !request.Now.Before(deletionTimestamp.Add(request.Policy.Settings().TerminationAge))
	if !result.ThresholdElapsed {
		return result, nil
	}

	collector := newCollector(request.Policy)
	settings := request.Policy.Settings()
	if settings.Diagnosis.CheckAPIServices {
		e.analyzeAPIServices(request, collector)
	}
	if settings.Diagnosis.CheckWebhooks {
		e.analyzeAdmissionWebhooks(request, target, collector)
	}

	switch groupResource {
	case namespaceResource.GroupResource():
		e.diagnoseNamespace(ctx, request, target, &result, collector)
	case crdResource.GroupResource():
		e.diagnoseCRD(ctx, request, target, &result, collector)
	default:
		e.diagnoseGeneric(request, target, collector)
	}
	var evidenceOverflow bool
	result.Findings, result.Actions, evidenceOverflow = collector.sorted()
	if evidenceOverflow {
		result.DiagnosisComplete = false
	}
	if !result.DiagnosisComplete {
		result.Actions = nil
	}
	return result, nil
}

func (e *Engine) getTarget(ctx context.Context, request Request) (*unstructured.Unstructured, schema.GroupVersionResource, error) {
	groupResource := schema.GroupResource{Group: request.Target.APIGroup, Resource: request.Target.Resource}
	resource, found := request.Snapshot.Catalog.Resolve(groupResource)
	if !found {
		gvr := groupResource.WithVersion(request.Target.Version)
		target, err := e.reader.Get(ctx, gvr, request.Target.Namespace, request.Target.Name)
		return target, gvr, err
	}
	var lastUnavailable error
	for _, version := range resource.OrderedVersions(request.Target.Version) {
		gvr := groupResource.WithVersion(version.Version)
		target, err := e.reader.Get(ctx, gvr, request.Target.Namespace, request.Target.Name)
		if err == nil {
			return target, gvr, nil
		}
		if !apierrors.IsNotFound(err) && !apierrors.IsGone(err) {
			return nil, gvr, err
		}
		lastUnavailable = err
	}
	return nil, groupResource.WithVersion(request.Target.Version), lastUnavailable
}

func (e *Engine) diagnoseGeneric(request Request, target *unstructured.Unstructured, collector *collector) {
	e.analyzeGracePeriod(request, target, collector)
	e.analyzeMetadataFinalizers(request, target, false, collector)
}

func (e *Engine) analyzeGracePeriod(request Request, target *unstructured.Unstructured, collector *collector) {
	grace := target.GetDeletionGracePeriodSeconds()
	deletionTimestamp := target.GetDeletionTimestamp()
	if grace == nil || deletionTimestamp == nil || !request.Now.After(deletionTimestamp.Time) {
		return
	}
	collector.addFinding(safetyv1alpha1.Finding{
		Type:        safetyv1alpha1.FindingDeletionGracePeriodExceeded,
		Message:     fmt.Sprintf("deletion grace period of %d seconds has elapsed", *grace),
		ResourceRef: targetReference(request.Target, target),
	})
}

func (e *Engine) analyzeMetadataFinalizers(request Request, target *unstructured.Unstructured, crd bool, collector *collector) {
	finalizers := sortedCopy(target.GetFinalizers())
	for _, finalizer := range finalizers {
		collector.addFinding(safetyv1alpha1.Finding{
			Type:        safetyv1alpha1.FindingBlockingFinalizer,
			Message:     fmt.Sprintf("metadata finalizer %q remains", finalizer),
			ResourceRef: targetReference(request.Target, target),
			Finalizer:   finalizer,
		})
		e.analyzeFinalizerOwner(request, finalizer, collector)

		actionType := safetyv1alpha1.ActionRemoveResourceFinalizer
		if crd && finalizer == apiextensionsv1.CustomResourceCleanupFinalizer {
			continue
		}
		collector.addAction(newAction(
			request.Policy,
			actionType,
			request.Target,
			finalizer,
			target.GetResourceVersion(),
			fmt.Sprintf("remove blocking metadata finalizer %q", finalizer),
		))
	}
}

type collector struct {
	policy          *policyengine.CompiledPolicy
	findings        map[string]safetyv1alpha1.Finding
	actions         map[string]safetyv1alpha1.RemediationAction
	persistedBytes  int
	omittedFindings int
	omittedActions  int
}

func newCollector(policy *policyengine.CompiledPolicy) *collector {
	return &collector{
		policy: policy, findings: make(map[string]safetyv1alpha1.Finding), actions: make(map[string]safetyv1alpha1.RemediationAction),
	}
}

func (c *collector) addFinding(finding safetyv1alpha1.Finding) {
	finding.Message = truncateRunes(finding.Message, 1024)
	finding.ID = findingID(finding)
	if _, exists := c.findings[finding.ID]; exists {
		return
	}
	encoded, err := json.Marshal(finding)
	if err != nil || len(c.findings) >= maxPersistedFindings || c.persistedBytes+len(encoded) > maxPersistedEvidenceBytes {
		c.omittedFindings++
		return
	}
	c.persistedBytes += len(encoded)
	c.findings[finding.ID] = finding
}

func (c *collector) addAction(action safetyv1alpha1.RemediationAction) {
	if _, exists := c.actions[action.ID]; exists {
		return
	}
	encoded, err := json.Marshal(action)
	if err != nil || len(c.actions) >= maxPersistedActions || c.persistedBytes+len(encoded) > maxPersistedEvidenceBytes {
		c.omittedActions++
		return
	}
	c.persistedBytes += len(encoded)
	c.actions[action.ID] = action
}

func (c *collector) sorted() ([]safetyv1alpha1.Finding, []safetyv1alpha1.RemediationAction, bool) {
	overflow := c.omittedFindings > 0 || c.omittedActions > 0
	findings := make([]safetyv1alpha1.Finding, 0, len(c.findings)+1)
	for _, finding := range c.findings {
		findings = append(findings, finding)
	}
	if overflow {
		omitted := int32(c.omittedFindings + c.omittedActions) // #nosec G115 -- diagnosis policy bounds cap this below int32 capacity.
		summary := safetyv1alpha1.Finding{
			Type: safetyv1alpha1.FindingUnknown, Message: "diagnostic evidence exceeded the persisted status budget",
			Count: &omitted, Truncated: true,
		}
		summary.ID = findingID(summary)
		findings = append(findings, summary)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	actions := make([]safetyv1alpha1.RemediationAction, 0, len(c.actions))
	for _, action := range c.actions {
		actions = append(actions, action)
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].ID < actions[j].ID })
	return findings, actions, overflow
}

func newAction(policy *policyengine.CompiledPolicy, actionType safetyv1alpha1.RemediationActionType, target safetyv1alpha1.TargetReference, finalizer, resourceVersion, reason string) safetyv1alpha1.RemediationAction {
	eligible, ineligibleReason := policy.ActionEligibility(actionType, finalizer)
	return safetyv1alpha1.RemediationAction{
		ID:                          actionID(actionType, target.UID, finalizer, resourceVersion, policy.UID(), policy.Generation()),
		Type:                        actionType,
		Risk:                        policyengine.RiskFor(actionType, finalizer),
		Target:                      target,
		Finalizer:                   finalizer,
		Eligible:                    eligible,
		IneligibleReason:            ineligibleReason,
		PreconditionResourceVersion: resourceVersion,
		Reason:                      reason,
	}
}

func findingID(finding safetyv1alpha1.Finding) string {
	parts := []string{string(finding.Type), finding.Message, finding.Finalizer, finding.APIService, finding.Webhook}
	if finding.ResourceRef != nil {
		parts = append(parts,
			finding.ResourceRef.APIGroup, finding.ResourceRef.Version, finding.ResourceRef.Resource,
			finding.ResourceRef.Namespace, finding.ResourceRef.Name, string(finding.ResourceRef.UID),
		)
	}
	if finding.ControllerRef != nil {
		parts = append(parts,
			finding.ControllerRef.APIVersion, finding.ControllerRef.Kind,
			finding.ControllerRef.Namespace, finding.ControllerRef.Name,
		)
	}
	if finding.Count != nil {
		parts = append(parts, fmt.Sprintf("%d", *finding.Count))
	}
	parts = append(parts, fmt.Sprintf("%t", finding.Truncated))
	return "finding-" + digest(parts...)
}

func actionID(actionType safetyv1alpha1.RemediationActionType, uid types.UID, finalizer, resourceVersion string, policyUID types.UID, policyGeneration int64) string {
	return "action-" + digest(string(actionType), string(uid), finalizer, resourceVersion, string(policyUID), strconv.FormatInt(policyGeneration, 10))
}

func digest(parts ...string) string {
	hasher := sha256.New()
	for i, part := range parts {
		if i > 0 {
			_, _ = hasher.Write([]byte{0})
		}
		_, _ = hasher.Write([]byte(part))
	}
	var sum [sha256.Size]byte
	return hex.EncodeToString(hasher.Sum(sum[:0]))
}

func targetReference(base safetyv1alpha1.TargetReference, object metav1.Object) *safetyv1alpha1.TargetReference {
	reference := base
	reference.Namespace = object.GetNamespace()
	reference.Name = object.GetName()
	reference.UID = object.GetUID()
	return &reference
}

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	slices.Sort(result)
	return result
}

func truncateRunes(value string, maximum int) string {
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	return string(runes[:maximum])
}
