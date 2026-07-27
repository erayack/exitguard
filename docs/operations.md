# Operations guide

## Before installation

1. Confirm the cluster runs a supported Kubernetes 1.33–1.35 release. Routine CI does not deploy; run `make test-e2e` with the target `K8S_VERSION` before release or installation.
2. Build, scan, and publish the image from the included Dockerfile.
3. Start with `config/default`. Review `config/remediation/executor-clusterrole.yaml` before enabling remediation.
4. Decide which identities may edit policies and create approvals. Bind the shipped roles explicitly; they have no subjects by default.
5. Configure Kubernetes audit retention for `remediationapprovals` create requests.

## Routine workflow

Check policy readiness and incidents without printing arbitrary target bodies:

```sh
kubectl get terminationpolicies
kubectl get deletionincidents
kubectl get deletionincident INCIDENT -o jsonpath='{.status.findings}'
kubectl get deletionincident INCIDENT -o jsonpath='{.status.recommendedActions}'
```

Copy the incident metadata UID and one current action ID into a new approval. Use the dry-run sample first:

```sh
kubectl apply -f config/samples/safety_v1alpha1_remediationapproval_dry-run.yaml
kubectl get remediationapproval example-dry-run
```

Do not modify and reuse an approval: its spec is immutable. Create a new named object for a persistent operation after reviewing dry-run status. Action IDs bind the target resource version and active policy UID/generation in addition to the action identity. If either changes, the refreshed incident has a new ID and a pending old approval becomes `Superseded` without mutation. Review the new evidence and create a new approval; never copy the old action ID forward. The executor also revalidates all state, so an approval can safely become `Expired` or `Failed` instead of mutating.

Tune evidence bounds independently in `spec.diagnosis`: `maxNamespaceObjects` limits objects enumerated for a terminating namespace, and `maxCRDInstances` limits custom-resource instances enumerated for a terminating CRD. Both default to 5000 and must be between 1 and 100000. A separate persisted-status budget retains at most 384 KiB of finding/action payload, 512 detailed findings, and 256 actions. Exceeding any persisted budget emits one count summary, marks diagnosis incomplete, and publishes no actions. Choose policy limits from expected inventory size and scanner/API-server cost rather than treating them as remediation switches.

## Recovery and degraded operation

- **Policy not Ready:** inspect status conditions. Fix invalid selectors or explicit resources absent from discovery. An unready policy does not match.
- **Discovery refresh errors:** the scanner retains the last complete catalog and reports errors through metrics/logs. Before any complete snapshot it fails closed. Restore API discovery or an unavailable aggregated API; do not lower diagnosis assertions.
- **DiagnosisFailed incident:** evidence was incomplete (for example, a list, webhook, conversion, or APIService check failed, or an enumeration/persisted-status bound was reached). A truncated finding is intentionally non-actionable: remediation remains blocked and recommended actions stay empty. Verify the actual inventory, correct the failed dependency or raise only the relevant policy bound, then wait for `DiagnosisComplete=True` and review the newly published action before creating another approval.
- **EvidenceExpired approval:** the scanner did not refresh the evidence deadline backing the action before execution. Restore scanner/discovery health and wait for a fresh active incident action; then create a new approval. The executor checks this deadline both before and after its per-target lock.
- **Approval APIError:** inspect the stable reason and Kubernetes API/audit logs. Correct availability, authorization, or admission failures and create a new approval if the incident action remains current. Never increase retry bounds to bypass a fail-closed admission webhook.
- **Executor unavailable:** diagnosis continues under the scanner. No automatic remediation occurs. Restore the executor only if the remediation profile is still intended.
- **Rollback to report-only:** delete the executor Deployment, its service account, bindings, namespaced leader-election Role/Binding, metrics Service, and `exitguard-executor` ClusterRole/Binding. Applying default alone does not prune remediation objects because `kubectl apply` is not a pruning deployment system.

## Retention

Active incidents remain durable. Once resolved, the scanner records a resolved time and uses the active policy's `resolvedIncidentTTL` annotation for cleanup. Deleting an incident garbage-collects executor-owned approvals. Export only the bounded API status or Kubernetes audit events required by your retention policy; avoid collecting arbitrary target object bodies.

## Metrics and alerts

Services expose authenticated HTTPS on port 8443. Bind the `exitguard-metrics-reader` ClusterRole to the chosen Prometheus service account outside this repository, then install the matching optional overlay. The supplied ServiceMonitors use the Prometheus pod's service-account token and tolerate the component's ephemeral self-signed serving certificate. Replace that trust choice in an environment overlay if organizational policy requires managed serving certificates.

Primary signals:

- `exitguard_scanner_cycles_total{result}` and cycle duration
- resource-list and diagnosis bounded results
- policy readiness and incident phase gauges
- `exitguard_discovery_refreshes_total{result}`
- `exitguard_remediation_attempts_total{action,risk,result,dry_run}`

No metric label contains object names, namespaces, UIDs, finalizers, error text, or Secret data.

## Irreversible operations

Finalizers are controller promises, not generic locks. Removing one can skip external cleanup, leak cloud resources, violate backup/retention workflows, or bypass storage protection. Removing the CRD cleanup finalizer can leave instances in storage while removing their API. Force-finalizing a namespace can make remaining objects inaccessible and can strand cluster-scoped or external dependencies.

For High or Critical actions:

1. establish why the owning controller cannot recover
2. inventory remaining objects and external assets independently
3. preserve incident and Kubernetes audit evidence
4. test API-server dry-run
5. obtain the organization's required human approval
6. execute once and verify both Kubernetes and external systems

There is no automatic rollback. Re-adding a finalizer after deletion does not restore skipped cleanup.
