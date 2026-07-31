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

// Package policy compiles TerminationPolicy objects into immutable runtime matchers.
package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
)

const (
	maxConditionMessageRunes        = 32_768
	conditionMessageTruncatedSuffix = "... (truncated)"

	// ConditionReady is true when a policy can participate in matching.
	ConditionReady = "Ready"
	// ConditionDiscoveryResolved is true when every explicit resource resolves.
	ConditionDiscoveryResolved = "DiscoveryResolved"
	// ConditionSelectorsValid is true when every label selector compiles.
	ConditionSelectorsValid = "SelectorsValid"
)

// Target contains the catalog identity and labels needed for side-effect-free matching.
type Target struct {
	GroupResource   schema.GroupResource
	Namespaced      bool
	Namespace       string
	Labels          map[string]string
	NamespaceLabels map[string]string
}

// Settings is a detached copy of policy limits used by diagnosis and remediation.
type Settings struct {
	TerminationAge      time.Duration
	Diagnosis           safetyv1alpha1.DiagnosisPolicy
	ApprovalTTL         time.Duration
	ResolvedIncidentTTL time.Duration
	MaxRisk             safetyv1alpha1.RiskLevel
	AllowNamespaceForce bool
}

type compiledRule struct {
	resources          map[schema.GroupResource]catalogdiscovery.Resource
	namespaceSelector  labels.Selector
	objectSelector     labels.Selector
	excludedNamespaces map[string]struct{}
}

// CompiledPolicy is immutable after Compile returns.
type CompiledPolicy struct {
	name              string
	uid               types.UID
	generation        int64
	priority          int32
	ready             bool
	rules             []compiledRule
	owners            map[string]safetyv1alpha1.ControllerReference
	allowedFinalizers map[string]struct{}
	settings          Settings
}

// Compile validates and resolves one policy against a catalog snapshot.
// Invalid policies are returned as non-ready matchers together with status conditions.
func Compile(source *safetyv1alpha1.TerminationPolicy, catalog catalogdiscovery.Snapshot, now time.Time) (*CompiledPolicy, safetyv1alpha1.TerminationPolicyStatus) {
	compiled := &CompiledPolicy{
		owners:            make(map[string]safetyv1alpha1.ControllerReference),
		allowedFinalizers: make(map[string]struct{}),
	}
	if source == nil {
		status := validationStatus(0, now, nil, nil, []string{"policy is nil"}, 0)
		return compiled, status
	}

	compiled.name = source.Name
	compiled.uid = source.UID
	compiled.generation = source.Generation
	compiled.priority = source.Spec.Priority
	compiled.settings = Settings{
		TerminationAge:      source.Spec.TerminationAge.Duration,
		Diagnosis:           source.Spec.Diagnosis,
		ApprovalTTL:         source.Spec.Remediation.ApprovalTTL.Duration,
		ResolvedIncidentTTL: source.Spec.Retention.ResolvedIncidentTTL.Duration,
		MaxRisk:             source.Spec.Remediation.MaxRisk,
		AllowNamespaceForce: source.Spec.Remediation.AllowNamespaceForce,
	}
	for _, owner := range source.Spec.FinalizerOwners {
		compiled.owners[owner.Finalizer] = owner.ControllerRef
	}
	for _, finalizer := range source.Spec.Remediation.AllowedFinalizers {
		compiled.allowedFinalizers[finalizer] = struct{}{}
	}

	selectorErrors := make([]string, 0)
	resolutionErrors := make([]string, 0)
	resolved := make(map[schema.GroupResource]struct{})
	// Resources are shared across compiled rules and must remain immutable.
	catalogResources := catalog.Resources()
	for index, rule := range source.Spec.TargetRules {
		compiledRule, selectorErrs := compileRuleSelectors(rule)
		for _, err := range selectorErrs {
			selectorErrors = append(selectorErrors, fmt.Sprintf("rule %d: %v", index, err))
		}

		for _, resource := range resolveRule(rule, catalogResources) {
			compiledRule.resources[resource.GroupResource] = resource
			resolved[resource.GroupResource] = struct{}{}
		}
		resolutionErrors = append(resolutionErrors, unresolvedSelections(index, rule, catalog, catalogResources)...)
		compiled.rules = append(compiled.rules, compiledRule)
	}

	configurationErrors := validateConfiguration(source.Spec)
	compiled.ready = len(selectorErrors) == 0 && len(resolutionErrors) == 0 && len(configurationErrors) == 0
	status := validationStatus(source.Generation, now, selectorErrors, resolutionErrors, configurationErrors, len(resolved))
	return compiled, status
}

// Name returns the source policy name.
func (p *CompiledPolicy) Name() string { return p.name }

// UID returns the source policy UID.
func (p *CompiledPolicy) UID() types.UID { return p.uid }

// Generation returns the source policy generation.
func (p *CompiledPolicy) Generation() int64 { return p.generation }

// Priority returns the source policy priority.
func (p *CompiledPolicy) Priority() int32 { return p.priority }

// Ready reports whether validation and discovery resolution succeeded.
func (p *CompiledPolicy) Ready() bool { return p != nil && p.ready }

// Settings returns a detached copy of compiled limits.
func (p *CompiledPolicy) Settings() Settings {
	if p == nil {
		return Settings{}
	}
	return p.settings
}

// ResolvedGroupResources returns the deterministic resource union selected by this policy.
func (p *CompiledPolicy) ResolvedGroupResources() []schema.GroupResource {
	if !p.Ready() {
		return nil
	}
	unique := make(map[schema.GroupResource]struct{})
	for _, rule := range p.rules {
		for groupResource := range rule.resources {
			unique[groupResource] = struct{}{}
		}
	}
	resources := make([]schema.GroupResource, 0, len(unique))
	for groupResource := range unique {
		resources = append(resources, groupResource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].String() < resources[j].String() })
	return resources
}

// FinalizerOwner resolves only exact, explicitly configured ownership mappings.
func (p *CompiledPolicy) FinalizerOwner(finalizer string) (safetyv1alpha1.ControllerReference, bool) {
	if p == nil {
		return safetyv1alpha1.ControllerReference{}, false
	}
	owner, found := p.owners[finalizer]
	return owner, found
}

// FinalizerOwners returns the deterministic set of controller workloads referenced by the policy.
func (p *CompiledPolicy) FinalizerOwners() []safetyv1alpha1.ControllerReference {
	if p == nil {
		return nil
	}
	unique := make(map[safetyv1alpha1.ControllerReference]struct{}, len(p.owners))
	for _, owner := range p.owners {
		unique[owner] = struct{}{}
	}
	owners := make([]safetyv1alpha1.ControllerReference, 0, len(unique))
	for owner := range unique {
		owners = append(owners, owner)
	}
	sort.Slice(owners, func(i, j int) bool {
		left := owners[i]
		right := owners[j]
		return left.Kind+"/"+left.Namespace+"/"+left.Name < right.Kind+"/"+right.Namespace+"/"+right.Name
	})
	return owners
}

// FinalizerAllowed reports whether finalizer appears in the exact remediation allowlist.
func (p *CompiledPolicy) FinalizerAllowed(finalizer string) bool {
	if p == nil {
		return false
	}
	_, found := p.allowedFinalizers[finalizer]
	return found
}

// Match reports whether a ready policy selects target.
func (p *CompiledPolicy) Match(target Target) bool {
	if !p.Ready() {
		return false
	}
	for _, rule := range p.rules {
		resource, found := rule.resources[target.GroupResource]
		if !found || resource.PreferredVersion.Namespaced != target.Namespaced {
			continue
		}
		if !rule.objectSelector.Matches(labels.Set(target.Labels)) {
			continue
		}
		if target.Namespaced {
			if _, excluded := rule.excludedNamespaces[target.Namespace]; excluded {
				continue
			}
			if !rule.namespaceSelector.Matches(labels.Set(target.NamespaceLabels)) {
				continue
			}
		}
		return true
	}
	return false
}

// SelectWinning returns the matching policy with highest priority, breaking ties by name.
func SelectWinning(policies []*CompiledPolicy, target Target) *CompiledPolicy {
	var winner *CompiledPolicy
	for _, candidate := range policies {
		if candidate == nil || !candidate.Match(target) {
			continue
		}
		if winner == nil || candidate.priority > winner.priority || (candidate.priority == winner.priority && candidate.name < winner.name) {
			winner = candidate
		}
	}
	return winner
}

// RiskFor returns the fixed operator risk for an action. Policy input cannot alter it.
func RiskFor(action safetyv1alpha1.RemediationActionType, finalizer string) safetyv1alpha1.RiskLevel {
	switch action {
	case safetyv1alpha1.ActionForceFinalizeNamespace:
		return safetyv1alpha1.RiskCritical
	case safetyv1alpha1.ActionRemoveCRDFinalizer:
		return safetyv1alpha1.RiskHigh
	case safetyv1alpha1.ActionRemoveResourceFinalizer:
		if isProtectiveFinalizer(finalizer) {
			return safetyv1alpha1.RiskHigh
		}
		return safetyv1alpha1.RiskMedium
	default:
		return safetyv1alpha1.RiskNone
	}
}

// AllowsAction applies compiled remediation limits to an operator-classified action.
func (p *CompiledPolicy) AllowsAction(action safetyv1alpha1.RemediationActionType, finalizer string) bool {
	allowed, _ := p.ActionEligibility(action, finalizer)
	return allowed
}

// ActionEligibility returns the policy decision and its stable ineligibility reason.
func (p *CompiledPolicy) ActionEligibility(action safetyv1alpha1.RemediationActionType, finalizer string) (bool, string) {
	if !p.Ready() {
		return false, "active policy is not ready"
	}
	if action == safetyv1alpha1.ActionForceFinalizeNamespace && !p.settings.AllowNamespaceForce {
		return false, "policy does not allow namespace force-finalization"
	}
	if action == safetyv1alpha1.ActionRemoveResourceFinalizer || action == safetyv1alpha1.ActionRemoveCRDFinalizer {
		if !p.FinalizerAllowed(finalizer) {
			return false, "finalizer is not in policy allowedFinalizers"
		}
	}
	risk := RiskFor(action, finalizer)
	if risk == safetyv1alpha1.RiskNone {
		return false, "action type is not supported"
	}
	if riskRank(risk) > riskRank(p.settings.MaxRisk) {
		return false, fmt.Sprintf("action risk %s exceeds policy maxRisk %s", risk, p.settings.MaxRisk)
	}
	return true, ""
}

func compileRuleSelectors(rule safetyv1alpha1.TargetRule) (compiledRule, []error) {
	compiled := compiledRule{
		resources:          make(map[schema.GroupResource]catalogdiscovery.Resource),
		namespaceSelector:  labels.Everything(),
		objectSelector:     labels.Everything(),
		excludedNamespaces: make(map[string]struct{}, len(rule.ExcludedNamespaces)),
	}
	for _, namespace := range rule.ExcludedNamespaces {
		compiled.excludedNamespaces[namespace] = struct{}{}
	}

	var errs []error
	if rule.NamespaceSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(rule.NamespaceSelector)
		if err != nil {
			errs = append(errs, fmt.Errorf("namespaceSelector: %w", err))
		} else {
			compiled.namespaceSelector = selector
		}
	}
	if rule.ObjectSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(rule.ObjectSelector)
		if err != nil {
			errs = append(errs, fmt.Errorf("objectSelector: %w", err))
		} else {
			compiled.objectSelector = selector
		}
	}
	return compiled, errs
}

func resolveRule(rule safetyv1alpha1.TargetRule, resources []catalogdiscovery.Resource) []catalogdiscovery.Resource {
	resourceWildcard := slices.Contains(rule.Resources, "*")
	resolved := make([]catalogdiscovery.Resource, 0)
	for _, resource := range resources {
		if !matchesToken(rule.APIGroups, resource.GroupResource.Group) || !matchesToken(rule.Resources, resource.GroupResource.Resource) {
			continue
		}
		if resourceWildcard && !resource.EligibleForWildcard() {
			continue
		}
		resolved = append(resolved, resource)
	}
	return resolved
}

func unresolvedSelections(index int, rule safetyv1alpha1.TargetRule, catalog catalogdiscovery.Snapshot, resources []catalogdiscovery.Resource) []string {
	exactGroups := withoutWildcard(rule.APIGroups)
	exactResources := withoutWildcard(rule.Resources)
	groupWildcard := slices.Contains(rule.APIGroups, "*")
	resourceWildcard := slices.Contains(rule.Resources, "*")
	var unresolved []string

	for _, group := range exactGroups {
		for _, resource := range exactResources {
			if _, found := catalog.Resolve(schema.GroupResource{Group: group, Resource: resource}); !found {
				unresolved = append(unresolved, formatSelection(index, group, resource))
			}
		}
	}
	if groupWildcard {
		for _, resource := range exactResources {
			if !anyResource(resources, func(candidate catalogdiscovery.Resource) bool {
				return candidate.GroupResource.Resource == resource
			}) {
				unresolved = append(unresolved, formatSelection(index, "*", resource))
			}
		}
	}
	if resourceWildcard {
		for _, group := range exactGroups {
			if !anyResource(resources, func(candidate catalogdiscovery.Resource) bool {
				return candidate.GroupResource.Group == group && candidate.EligibleForWildcard()
			}) {
				unresolved = append(unresolved, formatSelection(index, group, "*"))
			}
		}
		if groupWildcard && !anyResource(resources, func(candidate catalogdiscovery.Resource) bool {
			return candidate.EligibleForWildcard()
		}) {
			unresolved = append(unresolved, formatSelection(index, "*", "*"))
		}
	}
	return unresolved
}

func validateConfiguration(spec safetyv1alpha1.TerminationPolicySpec) []string {
	var errs []string
	if len(spec.TargetRules) == 0 {
		errs = append(errs, "at least one target rule is required")
	}
	for index, rule := range spec.TargetRules {
		if len(rule.APIGroups) == 0 {
			errs = append(errs, fmt.Sprintf("rule %d has no API groups", index))
		}
		if len(rule.Resources) == 0 {
			errs = append(errs, fmt.Sprintf("rule %d has no resources", index))
		}
	}
	if spec.TerminationAge.Duration <= 0 {
		errs = append(errs, "terminationAge must be positive")
	}
	if spec.Remediation.ApprovalTTL.Duration <= 0 {
		errs = append(errs, "approvalTTL must be positive")
	}
	if spec.Retention.ResolvedIncidentTTL.Duration <= 0 {
		errs = append(errs, "resolvedIncidentTTL must be positive")
	}
	if spec.Diagnosis.MaxNamespaceObjects < 1 || spec.Diagnosis.MaxNamespaceObjects > 100000 {
		errs = append(errs, "maxNamespaceObjects must be between 1 and 100000")
	}
	if spec.Diagnosis.MaxCRDInstances < 1 || spec.Diagnosis.MaxCRDInstances > 100000 {
		errs = append(errs, "maxCRDInstances must be between 1 and 100000")
	}
	if !validRisk(spec.Remediation.MaxRisk) {
		errs = append(errs, fmt.Sprintf("unknown maxRisk %q", spec.Remediation.MaxRisk))
	}
	for _, owner := range spec.FinalizerOwners {
		if owner.Finalizer == "" || strings.Contains(owner.Finalizer, "*") {
			errs = append(errs, fmt.Sprintf("finalizer owner %q must be an exact non-empty key", owner.Finalizer))
		}
	}
	for _, finalizer := range spec.Remediation.AllowedFinalizers {
		if finalizer == "" || strings.Contains(finalizer, "*") {
			errs = append(errs, fmt.Sprintf("allowed finalizer %q must be an exact non-empty key", finalizer))
		}
	}
	sort.Strings(errs)
	return errs
}

func validationStatus(generation int64, now time.Time, selectorErrors, resolutionErrors, configurationErrors []string, resolved int) safetyv1alpha1.TerminationPolicyStatus {
	validated := metav1.NewTime(now)
	selectorCondition := condition(ConditionSelectorsValid, generation, validated, len(selectorErrors) == 0, "ValidSelectors", "InvalidSelectors", selectorErrors)
	discoveryCondition := condition(ConditionDiscoveryResolved, generation, validated, len(resolutionErrors) == 0, "ResourcesResolved", "ResourcesUnresolved", resolutionErrors)
	readyErrors := append(append(append([]string(nil), selectorErrors...), resolutionErrors...), configurationErrors...)
	readyCondition := condition(ConditionReady, generation, validated, len(readyErrors) == 0, "Compiled", "InvalidPolicy", readyErrors)
	return safetyv1alpha1.TerminationPolicyStatus{
		ObservedGeneration:    generation,
		Conditions:            []metav1.Condition{readyCondition, discoveryCondition, selectorCondition},
		LastValidatedTime:     &validated,
		ResolvedResourceCount: int32(resolved), // #nosec G115 -- Kubernetes discovery cannot approach int32 capacity.
	}
}

func condition(conditionType string, generation int64, transitionTime metav1.Time, valid bool, validReason, invalidReason string, problems []string) metav1.Condition {
	status := metav1.ConditionTrue
	reason := validReason
	message := validReason
	if !valid {
		status = metav1.ConditionFalse
		reason = invalidReason
		message = truncateConditionMessage(strings.Join(problems, "; "))
	}
	return metav1.Condition{
		Type: conditionType, Status: status, ObservedGeneration: generation,
		LastTransitionTime: transitionTime, Reason: reason, Message: message,
	}
}

func matchesToken(tokens []string, value string) bool {
	return slices.Contains(tokens, "*") || slices.Contains(tokens, value)
}

func truncateConditionMessage(message string) string {
	runes := []rune(message)
	if len(runes) <= maxConditionMessageRunes {
		return message
	}
	suffix := []rune(conditionMessageTruncatedSuffix)
	return string(runes[:maxConditionMessageRunes-len(suffix)]) + conditionMessageTruncatedSuffix
}

func withoutWildcard(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "*" {
			result = append(result, value)
		}
	}
	return result
}

func anyResource(resources []catalogdiscovery.Resource, predicate func(catalogdiscovery.Resource) bool) bool {
	for _, resource := range resources {
		if predicate(resource) {
			return true
		}
	}
	return false
}

func formatSelection(index int, group, resource string) string {
	if group == "" {
		group = "core"
	}
	return fmt.Sprintf("rule %d: unresolved resource %s/%s", index, group, resource)
}

func isProtectiveFinalizer(finalizer string) bool {
	return finalizer == metav1.FinalizerDeleteDependents ||
		finalizer == "kubernetes.io/pv-protection" ||
		finalizer == "kubernetes.io/pvc-protection" ||
		finalizer == apiextensionsv1.CustomResourceCleanupFinalizer
}

func validRisk(risk safetyv1alpha1.RiskLevel) bool {
	switch risk {
	case safetyv1alpha1.RiskNone, safetyv1alpha1.RiskLow, safetyv1alpha1.RiskMedium, safetyv1alpha1.RiskHigh, safetyv1alpha1.RiskCritical:
		return true
	default:
		return false
	}
}

func riskRank(risk safetyv1alpha1.RiskLevel) int {
	switch risk {
	case safetyv1alpha1.RiskNone:
		return 0
	case safetyv1alpha1.RiskLow:
		return 1
	case safetyv1alpha1.RiskMedium:
		return 2
	case safetyv1alpha1.RiskHigh:
		return 3
	case safetyv1alpha1.RiskCritical:
		return 4
	default:
		return -1
	}
}
