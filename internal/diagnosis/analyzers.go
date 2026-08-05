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

package diagnosis

import (
	"context"
	"fmt"
	"slices"
	"sort"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
)

const metadataPageSize int64 = 500

func (e *Engine) analyzeAPIServices(request Request, collector *collector) {
	isNamespace := request.Target.APIGroup == "" && request.Target.Resource == "namespaces"
	for i := range request.Snapshot.APIServices {
		apiService := &request.Snapshot.APIServices[i]
		if apiServiceAvailable(apiService) {
			continue
		}
		if !isNamespace && (apiService.Spec.Group != request.Target.APIGroup || apiService.Spec.Version != request.Target.Version) {
			continue
		}
		message := fmt.Sprintf("APIService %q is unavailable", apiService.Name)
		for _, condition := range apiService.Status.Conditions {
			if condition.Type == apiregistrationv1.Available && condition.Status != apiregistrationv1.ConditionTrue && condition.Message != "" {
				message = fmt.Sprintf("APIService %q is unavailable: %s", apiService.Name, condition.Message)
				break
			}
		}
		collector.addFinding(safetyv1alpha1.Finding{
			Type: safetyv1alpha1.FindingUnavailableAPIService, Message: message, APIService: apiService.Name,
		})
	}
}

func apiServiceAvailable(apiService *apiregistrationv1.APIService) bool {
	for _, condition := range apiService.Status.Conditions {
		if condition.Type == apiregistrationv1.Available && condition.Status == apiregistrationv1.ConditionTrue {
			return true
		}
	}
	return false
}

func (e *Engine) diagnoseNamespace(ctx context.Context, request Request, target *unstructured.Unstructured, result *Result, collector *collector) {
	var namespace corev1.Namespace
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(target.Object, &namespace); err != nil {
		result.DiagnosisComplete = false
		collector.addFinding(safetyv1alpha1.Finding{
			Type: safetyv1alpha1.FindingDiscoveryFailure, Message: fmt.Sprintf("decode Namespace target: %v", err),
		})
		return
	}
	result.TargetSnapshot.NamespaceFinalizers = make([]string, len(namespace.Spec.Finalizers))
	for i, finalizer := range namespace.Spec.Finalizers {
		result.TargetSnapshot.NamespaceFinalizers[i] = string(finalizer)
	}
	sort.Strings(result.TargetSnapshot.NamespaceFinalizers)

	e.analyzeGracePeriod(request, target, collector)
	e.analyzeMetadataFinalizers(request, target, false, collector)
	e.analyzeNamespaceConditions(namespace.Status.Conditions, request.Target, collector)
	e.enumerateNamespace(ctx, request, result, collector)
	if result.DiagnosisComplete && len(namespace.Spec.Finalizers) > 0 {
		collector.addAction(newAction(
			request.Policy,
			safetyv1alpha1.ActionForceFinalizeNamespace,
			request.Target,
			"",
			target.GetResourceVersion(),
			"clear Namespace spec.finalizers after reviewing remaining content",
		))
	}
}

func (e *Engine) analyzeNamespaceConditions(conditions []corev1.NamespaceCondition, target safetyv1alpha1.TargetReference, collector *collector) {
	for _, condition := range conditions {
		if condition.Status != corev1.ConditionTrue {
			continue
		}
		findingType := safetyv1alpha1.FindingUnknown
		switch condition.Type {
		case corev1.NamespaceDeletionDiscoveryFailure, corev1.NamespaceDeletionGVParsingFailure, corev1.NamespaceDeletionContentFailure:
			findingType = safetyv1alpha1.FindingDiscoveryFailure
		case corev1.NamespaceContentRemaining:
			findingType = safetyv1alpha1.FindingRemainingResource
		case corev1.NamespaceFinalizersRemaining:
			findingType = safetyv1alpha1.FindingBlockingFinalizer
		}
		message := condition.Message
		if message == "" {
			message = fmt.Sprintf("Namespace condition %s is true", condition.Type)
		}
		collector.addFinding(safetyv1alpha1.Finding{
			Type: findingType, Message: message, ResourceRef: &target,
		})
	}
}

func (e *Engine) enumerateNamespace(ctx context.Context, request Request, result *Result, collector *collector) {
	resources := request.Snapshot.Catalog.Resources()
	maxObjects := int(request.Policy.Settings().Diagnosis.MaxNamespaceObjects)
	observed := 0
	for resourceIndex, resource := range resources {
		if !resource.PreferredVersion.Namespaced {
			continue
		}
		remaining := maxObjects - observed
		if remaining <= 0 {
			e.addTruncationFinding(observed, collector)
			result.DiagnosisComplete = false
			return
		}
		items, version, truncated, err := e.listNamespaceResource(ctx, resource, request.Target.Name, remaining)
		if err != nil {
			result.DiagnosisComplete = false
			collector.addFinding(safetyv1alpha1.Finding{
				Type:    safetyv1alpha1.FindingDiscoveryFailure,
				Message: fmt.Sprintf("list %s in Namespace %q: %v", resource.GroupResource, request.Target.Name, err),
			})
			continue
		}
		selectedResource := resource
		selectedResource.PreferredVersion = version
		for i := range items {
			item := &items[i]
			observed++
			reference := metadataReference(selectedResource, item)
			collector.addFinding(safetyv1alpha1.Finding{
				Type:        safetyv1alpha1.FindingRemainingResource,
				Message:     fmt.Sprintf("%s %s/%s remains in terminating Namespace", resource.GroupResource, item.Namespace, item.Name),
				ResourceRef: &reference,
			})
			if request.Policy.Settings().Diagnosis.CheckWebhooks {
				child := &unstructured.Unstructured{}
				child.SetLabels(item.Labels)
				childRequest := request
				childRequest.Target = reference
				e.analyzeAdmissionWebhooks(childRequest, child, collector)
			}
			for _, finalizer := range sortedCopy(item.Finalizers) {
				collector.addFinding(safetyv1alpha1.Finding{
					Type:        safetyv1alpha1.FindingBlockingFinalizer,
					Message:     fmt.Sprintf("remaining object has metadata finalizer %q", finalizer),
					ResourceRef: &reference, Finalizer: finalizer,
				})
				e.analyzeFinalizerOwner(request, finalizer, collector)
				collector.addAction(newAction(
					request.Policy,
					safetyv1alpha1.ActionRemoveResourceFinalizer,
					reference,
					finalizer,
					item.ResourceVersion,
					fmt.Sprintf("remove finalizer %q from object blocking Namespace deletion", finalizer),
				))
			}
		}
		if truncated || (observed >= maxObjects && hasLaterNamespacedResource(resources[resourceIndex+1:])) {
			e.addTruncationFinding(observed, collector)
			result.DiagnosisComplete = false
			return
		}
	}
}

func (e *Engine) listNamespaceResource(ctx context.Context, resource catalogdiscovery.Resource, namespace string, maximum int) ([]metav1.PartialObjectMetadata, catalogdiscovery.Version, bool, error) {
	var lastUnavailable error
	for _, version := range resource.OrderedVersions(resource.PreferredVersion.Version) {
		items := make([]metav1.PartialObjectMetadata, 0, min(maximum, int(metadataPageSize)))
		continueToken := ""
		for {
			remaining := maximum - len(items)
			if remaining <= 0 {
				return items, version, true, nil
			}
			list, err := e.reader.ListMetadata(ctx, resource.GroupResource.WithVersion(version.Version), namespace, metav1.ListOptions{Limit: min(metadataPageSize, int64(remaining)), Continue: continueToken})
			if err != nil {
				if apierrors.IsNotFound(err) || apierrors.IsGone(err) {
					lastUnavailable = err
					break
				}
				return nil, version, false, err
			}
			items = append(items, list.Items...)
			continueToken = list.Continue
			if continueToken == "" {
				return items, version, false, nil
			}
		}
	}
	return nil, resource.PreferredVersion, false, lastUnavailable
}

func (e *Engine) addTruncationFinding(observed int, collector *collector) {
	count := int32(observed) // #nosec G115 -- bounded by the policy's int32 maximum.
	collector.addFinding(safetyv1alpha1.Finding{
		Type:    safetyv1alpha1.FindingRemainingResource,
		Message: "remaining-resource enumeration reached maxNamespaceObjects",
		Count:   &count, Truncated: true,
	})
}

func hasLaterNamespacedResource(resources []catalogdiscovery.Resource) bool {
	return slices.ContainsFunc(resources, func(resource catalogdiscovery.Resource) bool {
		return resource.PreferredVersion.Namespaced
	})
}

func metadataReference(resource catalogdiscovery.Resource, object metav1.Object) safetyv1alpha1.TargetReference {
	return safetyv1alpha1.TargetReference{
		APIGroup:  resource.GroupResource.Group,
		Version:   resource.PreferredVersion.Version,
		Resource:  resource.GroupResource.Resource,
		Kind:      resource.PreferredVersion.Kind,
		Namespace: object.GetNamespace(), Name: object.GetName(), UID: object.GetUID(),
	}
}

func (e *Engine) diagnoseCRD(ctx context.Context, request Request, target *unstructured.Unstructured, result *Result, collector *collector) {
	var crd apiextensionsv1.CustomResourceDefinition
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(target.Object, &crd); err != nil {
		result.DiagnosisComplete = false
		collector.addFinding(safetyv1alpha1.Finding{
			Type: safetyv1alpha1.FindingDiscoveryFailure, Message: fmt.Sprintf("decode CustomResourceDefinition target: %v", err),
		})
		return
	}

	e.analyzeGracePeriod(request, target, collector)
	e.analyzeMetadataFinalizers(request, target, true, collector)
	maxInstances := int(request.Policy.Settings().Diagnosis.MaxCRDInstances)
	instancesComplete := e.enumerateCRDInstances(ctx, &crd, maxInstances, collector)
	conversionComplete := e.analyzeCRDConversion(request, &crd, collector)
	result.DiagnosisComplete = result.DiagnosisComplete && instancesComplete && conversionComplete

	if instancesComplete && conversionComplete && slices.Contains(crd.Finalizers, apiextensionsv1.CustomResourceCleanupFinalizer) {
		collector.addAction(newAction(
			request.Policy,
			safetyv1alpha1.ActionRemoveCRDFinalizer,
			request.Target,
			apiextensionsv1.CustomResourceCleanupFinalizer,
			target.GetResourceVersion(),
			"remove the CRD cleanup finalizer after complete instance and conversion evidence",
		))
	}
}

func (e *Engine) enumerateCRDInstances(ctx context.Context, crd *apiextensionsv1.CustomResourceDefinition, maxInstances int, collector *collector) bool {
	versions := make([]string, 0, len(crd.Spec.Versions))
	for _, version := range crd.Spec.Versions {
		if version.Served {
			versions = append(versions, version.Name)
		}
	}
	sort.Strings(versions)
	seenUIDs := make(map[string]struct{}, maxInstances)
	retained := 0
	complete := true
	for _, version := range versions {
		gvr := schema.GroupVersionResource{Group: crd.Spec.Group, Version: version, Resource: crd.Spec.Names.Plural}
		nextPage := ""
		for {
			list, err := e.reader.ListMetadata(ctx, gvr, "", metav1.ListOptions{Limit: metadataPageSize, Continue: nextPage})
			if err != nil {
				complete = false
				collector.addFinding(safetyv1alpha1.Finding{
					Type:    safetyv1alpha1.FindingDiscoveryFailure,
					Message: fmt.Sprintf("list CRD instances for %s: %v", gvr.GroupVersion().String(), err),
				})
				break
			}
			for i := range list.Items {
				item := &list.Items[i]
				uid := string(item.UID)
				if uid != "" {
					if _, found := seenUIDs[uid]; found {
						continue
					}
				}
				if retained >= maxInstances {
					e.addCRDTruncationFinding(retained, collector)
					return false
				}
				retained++
				if uid == "" {
					complete = false
					collector.addFinding(safetyv1alpha1.Finding{
						Type:    safetyv1alpha1.FindingUnknown,
						Message: fmt.Sprintf("CRD instance %s/%s in %s has no UID", item.Namespace, item.Name, gvr.GroupVersion()),
					})
					continue
				}
				seenUIDs[uid] = struct{}{}
				reference := safetyv1alpha1.TargetReference{
					APIGroup: crd.Spec.Group, Version: version, Resource: crd.Spec.Names.Plural, Kind: crd.Spec.Names.Kind,
					Namespace: item.Namespace, Name: item.Name, UID: item.UID,
				}
				collector.addFinding(safetyv1alpha1.Finding{
					Type:        safetyv1alpha1.FindingRemainingResource,
					Message:     fmt.Sprintf("custom resource %s/%s remains", item.Namespace, item.Name),
					ResourceRef: &reference,
				})
			}
			nextPage = list.Continue
			if nextPage == "" {
				break
			}
		}
	}
	return complete
}

func (e *Engine) addCRDTruncationFinding(retained int, collector *collector) {
	count := int32(retained) // #nosec G115 -- bounded by the policy's int32 maximum.
	collector.addFinding(safetyv1alpha1.Finding{
		Type:    safetyv1alpha1.FindingRemainingResource,
		Message: "custom-resource enumeration reached maxCRDInstances",
		Count:   &count, Truncated: true,
	})
}

func (e *Engine) analyzeCRDConversion(request Request, crd *apiextensionsv1.CustomResourceDefinition, collector *collector) bool {
	if crd.Spec.Conversion == nil || crd.Spec.Conversion.Strategy != apiextensionsv1.WebhookConverter {
		return true
	}
	if crd.Spec.Conversion.Webhook == nil {
		collector.addFinding(safetyv1alpha1.Finding{
			Type: safetyv1alpha1.FindingUnknown, Message: "CRD conversion webhook configuration is missing",
		})
		return false
	}
	clientConfig := crd.Spec.Conversion.Webhook.ClientConfig
	if clientConfig == nil {
		collector.addFinding(safetyv1alpha1.Finding{
			Type:    safetyv1alpha1.FindingUnknown,
			Message: "CRD conversion webhook client configuration is missing", Webhook: crd.Name + "/conversion",
		})
		return false
	}
	if clientConfig.URL != nil {
		collector.addFinding(safetyv1alpha1.Finding{
			Type:    safetyv1alpha1.FindingUnknown,
			Message: "CRD conversion URL health is not probed", Webhook: crd.Name + "/conversion",
		})
		return false
	}
	if clientConfig.Service == nil {
		collector.addFinding(safetyv1alpha1.Finding{
			Type:    safetyv1alpha1.FindingUnknown,
			Message: "CRD conversion webhook has no Service or URL", Webhook: crd.Name + "/conversion",
		})
		return false
	}
	ready, reason := serviceBackendReady(request.Snapshot, clientConfig.Service.Namespace, clientConfig.Service.Name)
	if !ready {
		collector.addFinding(safetyv1alpha1.Finding{
			Type:    safetyv1alpha1.FindingBlockingWebhook,
			Message: fmt.Sprintf("CRD conversion Service is unavailable: %s", reason), Webhook: crd.Name + "/conversion",
		})
		return false
	}
	return true
}

func (e *Engine) analyzeFinalizerOwner(request Request, finalizer string, collector *collector) {
	owner, configured := request.Policy.FinalizerOwner(finalizer)
	if !configured {
		return
	}
	healthy, reason := ownerHealthy(request.Snapshot, owner)
	if healthy {
		return
	}
	collector.addFinding(safetyv1alpha1.Finding{
		Type:      safetyv1alpha1.FindingMissingFinalizerController,
		Message:   fmt.Sprintf("configured finalizer owner is unhealthy: %s", reason),
		Finalizer: finalizer, ControllerRef: &owner,
	})
}

func ownerHealthy(snapshot Snapshot, owner safetyv1alpha1.ControllerReference) (bool, string) {
	switch owner.Kind {
	case "Deployment":
		for i := range snapshot.Deployments {
			workload := &snapshot.Deployments[i]
			if workload.Namespace == owner.Namespace && workload.Name == owner.Name {
				desired := int32(1)
				if workload.Spec.Replicas != nil {
					desired = *workload.Spec.Replicas
				}
				if desired == 0 || workload.Status.ObservedGeneration < workload.Generation || workload.Status.AvailableReplicas < desired {
					return false, "Deployment is not fully available at its current generation"
				}
				return true, ""
			}
		}
		return false, "Deployment does not exist"
	case "StatefulSet":
		for i := range snapshot.StatefulSets {
			workload := &snapshot.StatefulSets[i]
			if workload.Namespace == owner.Namespace && workload.Name == owner.Name {
				desired := int32(1)
				if workload.Spec.Replicas != nil {
					desired = *workload.Spec.Replicas
				}
				if desired == 0 || workload.Status.ObservedGeneration < workload.Generation || workload.Status.ReadyReplicas < desired {
					return false, "StatefulSet is not fully ready at its current generation"
				}
				return true, ""
			}
		}
		return false, "StatefulSet does not exist"
	case "DaemonSet":
		for i := range snapshot.DaemonSets {
			workload := &snapshot.DaemonSets[i]
			if workload.Namespace == owner.Namespace && workload.Name == owner.Name {
				if workload.Status.ObservedGeneration < workload.Generation || workload.Status.DesiredNumberScheduled == 0 || workload.Status.NumberReady < workload.Status.DesiredNumberScheduled {
					return false, "DaemonSet is not fully ready at its current generation"
				}
				return true, ""
			}
		}
		return false, "DaemonSet does not exist"
	default:
		return false, fmt.Sprintf("unsupported owner kind %q", owner.Kind)
	}
}

func (e *Engine) analyzeAdmissionWebhooks(request Request, target *unstructured.Unstructured, collector *collector) {
	for i := range request.Snapshot.MutatingWebhooks {
		configuration := &request.Snapshot.MutatingWebhooks[i]
		for j := range configuration.Webhooks {
			webhook := &configuration.Webhooks[j]
			e.analyzeWebhook(request, target, webhookView{
				identity: configuration.Name + "/" + webhook.Name,
				rules:    webhook.Rules, failurePolicy: webhook.FailurePolicy, matchPolicy: webhook.MatchPolicy,
				namespaceSelector: webhook.NamespaceSelector, objectSelector: webhook.ObjectSelector,
				clientConfig: webhook.ClientConfig, matchConditions: len(webhook.MatchConditions),
			}, collector)
		}
	}
	for i := range request.Snapshot.ValidatingWebhooks {
		configuration := &request.Snapshot.ValidatingWebhooks[i]
		for j := range configuration.Webhooks {
			webhook := &configuration.Webhooks[j]
			e.analyzeWebhook(request, target, webhookView{
				identity: configuration.Name + "/" + webhook.Name,
				rules:    webhook.Rules, failurePolicy: webhook.FailurePolicy, matchPolicy: webhook.MatchPolicy,
				namespaceSelector: webhook.NamespaceSelector, objectSelector: webhook.ObjectSelector,
				clientConfig: webhook.ClientConfig, matchConditions: len(webhook.MatchConditions),
			}, collector)
		}
	}
}

type webhookView struct {
	identity          string
	rules             []admissionv1.RuleWithOperations
	failurePolicy     *admissionv1.FailurePolicyType
	matchPolicy       *admissionv1.MatchPolicyType
	namespaceSelector *metav1.LabelSelector
	objectSelector    *metav1.LabelSelector
	clientConfig      admissionv1.WebhookClientConfig
	matchConditions   int
}

func (e *Engine) analyzeWebhook(request Request, target *unstructured.Unstructured, webhook webhookView, collector *collector) {
	if webhook.failurePolicy != nil && *webhook.failurePolicy == admissionv1.Ignore {
		return
	}
	matches, uncertain := webhookMatches(request, target, webhook)
	if uncertain != "" {
		collector.addFinding(safetyv1alpha1.Finding{
			Type: safetyv1alpha1.FindingUnknown, Message: uncertain, Webhook: webhook.identity, ResourceRef: &request.Target,
		})
		return
	}
	if !matches {
		return
	}
	if webhook.matchConditions > 0 {
		collector.addFinding(safetyv1alpha1.Finding{
			Type:    safetyv1alpha1.FindingUnknown,
			Message: "matching webhook has matchConditions that cannot be evaluated from metadata", Webhook: webhook.identity, ResourceRef: &request.Target,
		})
		return
	}
	if webhook.clientConfig.URL != nil {
		collector.addFinding(safetyv1alpha1.Finding{
			Type:    safetyv1alpha1.FindingUnknown,
			Message: "matching fail-closed webhook URL health is not probed", Webhook: webhook.identity, ResourceRef: &request.Target,
		})
		return
	}
	if webhook.clientConfig.Service == nil {
		collector.addFinding(safetyv1alpha1.Finding{
			Type:    safetyv1alpha1.FindingUnknown,
			Message: "matching fail-closed webhook has no Service or URL", Webhook: webhook.identity, ResourceRef: &request.Target,
		})
		return
	}
	service := webhook.clientConfig.Service
	ready, reason := serviceBackendReady(request.Snapshot, service.Namespace, service.Name)
	if !ready {
		collector.addFinding(safetyv1alpha1.Finding{
			Type:    safetyv1alpha1.FindingBlockingWebhook,
			Message: fmt.Sprintf("matching fail-closed webhook backend is unavailable: %s", reason), Webhook: webhook.identity, ResourceRef: &request.Target,
		})
		return
	}
	collector.addFinding(safetyv1alpha1.Finding{
		Type:    safetyv1alpha1.FindingUnknown,
		Message: "matching fail-closed webhook backend is ready; TLS behavior was not probed", Webhook: webhook.identity, ResourceRef: &request.Target,
	})
}

func webhookMatches(request Request, target *unstructured.Unstructured, webhook webhookView) (bool, string) {
	if webhook.namespaceSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(webhook.namespaceSelector)
		if err != nil {
			return false, fmt.Sprintf("matching webhook has an invalid namespaceSelector: %v", err)
		}
		var selectedLabels map[string]string
		evaluateSelector := false
		switch {
		case request.Target.APIGroup == "" && request.Target.Resource == "namespaces":
			selectedLabels = target.GetLabels()
			evaluateSelector = true
		case request.Target.Namespace != "":
			selectedLabels = request.Snapshot.NamespaceLabels[request.Target.Namespace]
			evaluateSelector = true
		}
		if evaluateSelector && !selector.Matches(labels.Set(selectedLabels)) {
			return false, ""
		}
	}
	if webhook.objectSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(webhook.objectSelector)
		if err != nil {
			return false, fmt.Sprintf("matching webhook has an invalid objectSelector: %v", err)
		}
		if !selector.Matches(labels.Set(target.GetLabels())) {
			return false, ""
		}
	}
	for _, rule := range webhook.rules {
		if ruleMatches(request, rule, webhook.matchPolicy) {
			return true, ""
		}
	}
	return false, ""
}

func ruleMatches(request Request, rule admissionv1.RuleWithOperations, matchPolicy *admissionv1.MatchPolicyType) bool {
	targetResource, subresource := admissionTarget(request.Target)
	if !operationMatches(rule.Operations) || !stringRuleMatches(rule.APIGroups, request.Target.APIGroup) || !resourceRuleMatches(rule.Resources, targetResource, subresource) {
		return false
	}
	if !scopeMatches(rule.Scope, request.Target.Namespace != "") {
		return false
	}
	if stringRuleMatches(rule.APIVersions, request.Target.Version) {
		return true
	}
	if matchPolicy != nil && *matchPolicy == admissionv1.Exact {
		return false
	}
	catalogResource, found := request.Snapshot.Catalog.Resolve(schema.GroupResource{Group: request.Target.APIGroup, Resource: request.Target.Resource})
	if !found {
		return false
	}
	versions := []string{catalogResource.PreferredVersion.Version}
	for _, alternate := range catalogResource.AlternateVersions() {
		versions = append(versions, alternate.Version)
	}
	return slices.ContainsFunc(versions, func(version string) bool {
		return stringRuleMatches(rule.APIVersions, version)
	})
}

func operationMatches(operations []admissionv1.OperationType) bool {
	return slices.Contains(operations, admissionv1.OperationAll) || slices.Contains(operations, admissionv1.Update)
}

func stringRuleMatches(rules []string, value string) bool {
	return slices.Contains(rules, "*") || slices.Contains(rules, value)
}

func admissionTarget(target safetyv1alpha1.TargetReference) (string, string) {
	if target.APIGroup == "" && target.Resource == "namespaces" {
		return target.Resource, "finalize"
	}
	return target.Resource, ""
}

func resourceRuleMatches(rules []string, resource, subresource string) bool {
	candidate := resource
	if subresource != "" {
		candidate += "/" + subresource
	}
	for _, rule := range rules {
		switch {
		case rule == "*/*", rule == candidate:
			return true
		case rule == "*" && subresource == "":
			return true
		case subresource != "" && rule == resource+"/*":
			return true
		case subresource != "" && rule == "*/"+subresource:
			return true
		}
	}
	return false
}

func scopeMatches(scope *admissionv1.ScopeType, namespaced bool) bool {
	if scope == nil || *scope == admissionv1.AllScopes {
		return true
	}
	return namespaced && *scope == admissionv1.NamespacedScope || !namespaced && *scope == admissionv1.ClusterScope
}

func serviceBackendReady(snapshot Snapshot, namespace, name string) (bool, string) {
	serviceFound := slices.ContainsFunc(snapshot.Services, func(service corev1.Service) bool {
		return service.Namespace == namespace && service.Name == name
	})
	if !serviceFound {
		return false, fmt.Sprintf("Service %s/%s does not exist", namespace, name)
	}
	for _, endpointSlice := range snapshot.EndpointSlices {
		if endpointSlice.Namespace != namespace || endpointSlice.Labels[discoveryv1.LabelServiceName] != name {
			continue
		}
		for _, endpoint := range endpointSlice.Endpoints {
			// EndpointSlice readiness defaults to true when the condition is omitted.
			if endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready {
				return true, ""
			}
		}
	}
	return false, fmt.Sprintf("Service %s/%s has no ready EndpointSlice endpoints", namespace, name)
}
