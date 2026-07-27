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

package manifests_test

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestDeploymentProfilesAndPermissionBoundary(t *testing.T) {
	defaultObjects := render(t, "config/default")
	remediationObjects := render(t, "config/remediation")

	if find(defaultObjects, "Deployment", "exitguard-executor") != nil {
		t.Fatal("default profile must not contain the executor Deployment")
	}
	if find(defaultObjects, "ServiceAccount", "exitguard-executor") != nil {
		t.Fatal("default profile must not contain the executor ServiceAccount")
	}

	scannerRole := required(t, defaultObjects, "ClusterRole", "exitguard-scanner")
	assertRule(t, scannerRole, []string{"*"}, []string{"*"}, []string{"get", "list"})
	for _, forbidden := range []struct {
		resource string
		verb     string
	}{
		{resource: "*", verb: "delete"},
		{resource: "namespaces/finalize", verb: "update"},
		{resource: "remediationapprovals/status", verb: "patch"},
	} {
		if permits(scannerRole, forbidden.resource, forbidden.verb) {
			t.Fatalf("scanner role unexpectedly grants %s on %s", forbidden.verb, forbidden.resource)
		}
	}

	executorRole := required(t, remediationObjects, "ClusterRole", "exitguard-executor")
	assertRule(t, executorRole, []string{"", "apps", "apiextensions.k8s.io"}, []string{"*"}, []string{"get", "patch"})
	assertRule(t, executorRole, []string{""}, []string{"namespaces/finalize"}, []string{"update"})
	assertRule(t, executorRole, []string{"events.k8s.io"}, []string{"events"}, []string{"create", "patch", "update"})
	for _, group := range []string{"*", "safety.exitguard.io", "admissionregistration.k8s.io", "apiregistration.k8s.io", "rbac.authorization.k8s.io"} {
		if permitsGroupWildcardWrite(executorRole, group) {
			t.Fatalf("executor role unexpectedly grants mutation in API group %q", group)
		}
	}
	for _, forbidden := range []struct {
		resource string
		verb     string
	}{
		{resource: "*", verb: "list"},
		{resource: "*", verb: "delete"},
		{resource: "terminationpolicies/status", verb: "update"},
		{resource: "deletionincidents/status", verb: "update"},
	} {
		if explicitlyPermits(executorRole, forbidden.resource, forbidden.verb) {
			t.Fatalf("executor role unexpectedly contains an explicit %s grant on %s", forbidden.verb, forbidden.resource)
		}
	}

	assertHardenedDeployment(t, required(t, defaultObjects, "Deployment", "exitguard-scanner"), "scanner", "exitguard-scanner")
	assertHardenedDeployment(t, required(t, remediationObjects, "Deployment", "exitguard-executor"), "executor", "exitguard-executor")
}

func TestMetricsAndUserRoles(t *testing.T) {
	objects := render(t, "config/remediation")
	metricsReader := required(t, objects, "ClusterRole", "exitguard-metrics-reader")
	rules, _, _ := unstructured.NestedSlice(metricsReader.Object, "rules")
	if len(rules) != 1 || !explicitlyPermits(metricsReader, "/metrics", "get") {
		t.Fatal("metrics reader must contain exactly one GET /metrics rule")
	}

	approver := required(t, objects, "ClusterRole", "exitguard-approver")
	if !permits(approver, "remediationapprovals", "create") {
		t.Fatal("approver must be able to create remediation approvals")
	}
	for _, verb := range []string{"update", "patch", "delete"} {
		if permits(approver, "remediationapprovals", verb) {
			t.Fatalf("approver must not be able to %s remediation approvals", verb)
		}
	}

	for _, component := range []string{"scanner", "executor"} {
		required(t, objects, "Service", "exitguard-"+component+"-metrics")
		required(t, objects, "ClusterRoleBinding", "exitguard-"+component+"-auth-delegator")
		authReader := required(t, objects, "RoleBinding", "exitguard-"+component+"-authentication-reader")
		if authReader.GetNamespace() != "kube-system" {
			t.Fatalf("%s authentication reader binding must be in kube-system", component)
		}
	}
}

func TestOptionalAndSampleOverlaysRender(t *testing.T) {
	for _, path := range []string{
		"config/prometheus/report-only",
		"config/prometheus/remediation",
		"config/samples",
	} {
		if objects := render(t, path); len(objects) == 0 {
			t.Fatalf("%s rendered no objects", path)
		}
	}
}

func render(t *testing.T, path string) []*unstructured.Unstructured {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	command := exec.Command("kubectl", "kustomize", filepath.Join(root, path))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("render %s: %v\n%s", path, err, output)
	}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
	var objects []*unstructured.Unstructured
	for {
		var raw map[string]interface{}
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("decode %s: %v", path, err)
		}
		if len(raw) != 0 {
			objects = append(objects, &unstructured.Unstructured{Object: raw})
		}
	}
	return objects
}

func find(objects []*unstructured.Unstructured, kind, name string) *unstructured.Unstructured {
	for _, object := range objects {
		if object.GetKind() == kind && object.GetName() == name {
			return object
		}
	}
	return nil
}

func required(t *testing.T, objects []*unstructured.Unstructured, kind, name string) *unstructured.Unstructured {
	t.Helper()
	object := find(objects, kind, name)
	if object == nil {
		t.Fatalf("missing %s %s", kind, name)
	}
	return object
}

func assertRule(t *testing.T, role *unstructured.Unstructured, apiGroups, resources, verbs []string) {
	t.Helper()
	rules, _, _ := unstructured.NestedSlice(role.Object, "rules")
	for _, item := range rules {
		rule := item.(map[string]interface{})
		if hasAll(strings(rule["apiGroups"]), apiGroups) && hasAll(strings(rule["resources"]), resources) && hasAll(strings(rule["verbs"]), verbs) {
			return
		}
	}
	t.Fatalf("%s %s lacks rule groups=%v resources=%v verbs=%v", role.GetKind(), role.GetName(), apiGroups, resources, verbs)
}

func permits(role *unstructured.Unstructured, resource, verb string) bool {
	rules, _, _ := unstructured.NestedSlice(role.Object, "rules")
	for _, item := range rules {
		rule := item.(map[string]interface{})
		resources := append(strings(rule["resources"]), strings(rule["nonResourceURLs"])...)
		if (contains(resources, resource) || contains(resources, "*")) && (contains(strings(rule["verbs"]), verb) || contains(strings(rule["verbs"]), "*")) {
			return true
		}
	}
	return false
}

func permitsGroupWildcardWrite(role *unstructured.Unstructured, group string) bool {
	rules, _, _ := unstructured.NestedSlice(role.Object, "rules")
	for _, item := range rules {
		rule := item.(map[string]interface{})
		if contains(strings(rule["apiGroups"]), group) && contains(strings(rule["resources"]), "*") && (contains(strings(rule["verbs"]), "patch") || contains(strings(rule["verbs"]), "update") || contains(strings(rule["verbs"]), "delete") || contains(strings(rule["verbs"]), "*")) {
			return true
		}
	}
	return false
}

func explicitlyPermits(role *unstructured.Unstructured, resource, verb string) bool {
	rules, _, _ := unstructured.NestedSlice(role.Object, "rules")
	for _, item := range rules {
		rule := item.(map[string]interface{})
		resources := append(strings(rule["resources"]), strings(rule["nonResourceURLs"])...)
		if contains(resources, resource) && (contains(strings(rule["verbs"]), verb) || contains(strings(rule["verbs"]), "*")) {
			return true
		}
	}
	return false
}

func assertHardenedDeployment(t *testing.T, deployment *unstructured.Unstructured, component, serviceAccount string) {
	t.Helper()
	podSpec, _, _ := unstructured.NestedMap(deployment.Object, "spec", "template", "spec")
	if podSpec["serviceAccountName"] != serviceAccount {
		t.Fatalf("%s uses wrong service account", component)
	}
	security := podSpec["securityContext"].(map[string]interface{})
	if security["runAsNonRoot"] != true {
		t.Fatalf("%s pod must run as non-root", component)
	}
	containers := podSpec["containers"].([]interface{})
	container := containers[0].(map[string]interface{})
	args := strings(container["args"])
	for _, requiredArg := range []string{"--component=" + component, "--metrics-bind-address=:8443", "--metrics-secure=true", "--health-probe-bind-address=:8081"} {
		if !contains(args, requiredArg) {
			t.Fatalf("%s missing argument %s", component, requiredArg)
		}
	}
	containerSecurity := container["securityContext"].(map[string]interface{})
	if containerSecurity["allowPrivilegeEscalation"] != false || containerSecurity["readOnlyRootFilesystem"] != true {
		t.Fatalf("%s container security context is not hardened", component)
	}
	if _, ok := container["resources"]; !ok {
		t.Fatalf("%s has no resource bounds", component)
	}
	for _, probe := range []string{"livenessProbe", "readinessProbe"} {
		if _, ok := container[probe]; !ok {
			t.Fatalf("%s has no %s", component, probe)
		}
	}
}

func strings(value interface{}) []string {
	items, _ := value.([]interface{})
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.(string))
	}
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func hasAll(values, wanted []string) bool {
	for _, value := range wanted {
		if !contains(values, value) {
			return false
		}
	}
	return true
}
