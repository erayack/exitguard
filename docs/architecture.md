# Architecture

## Process boundary

One image runs one of two controller-runtime manager modes selected by `--component`:

- **scanner**: periodically refreshes API discovery, compiles policies, lists target metadata with bounded concurrency and pagination, performs side-effect-free diagnosis, and owns policy status plus incident lifecycle.
- **executor**: watches immutable approvals, revalidates current state, and performs one preconditioned API operation. It does not participate in scanning or incident writes.

Each mode has a distinct leader-election identity (`scanner.safety.exitguard.io` or `executor.safety.exitguard.io`) and service account. The default Kustomize profile contains no executor object or target patch grant. The remediation overlay adds the executor Deployment and its dangerous RBAC atomically.

## Discovery and degraded behavior

The discovery catalog publishes only complete snapshots. A failed or partial refresh increments a bounded-result metric and retains the last complete snapshot; it never replaces known-good discovery with partial data. Before the first successful snapshot, scanner cycles fail closed and create no diagnosis based on incomplete coverage. Explicit policy resources that do not resolve make that policy unready. Incident resolution also respects scan coverage so a list failure is not mistaken for target disappearance.

## Policy and incident lifecycle

Policies are compiled on each scan. Selectors and explicit discovery references are validated, then matching uses REST `GroupResource`, scope, labels, and exact exclusions. Highest priority wins and lexicographically smallest name breaks ties.

An incident name is deterministic for a target UID. Its immutable spec pins the target identity and first observation; scanner-owned status contains current diagnosis, target snapshot, active policy revision, findings, actions, and lifecycle conditions. When a target disappears, is replaced, or leaves policy scope, the scanner resolves rather than rewrites its identity. Resolved incidents are deleted after the winning policy's retention TTL; owner-referenced approvals are then garbage-collected.

Evidence collection uses separate policy limits: `maxNamespaceObjects` bounds remaining-object enumeration for one terminating namespace, while `maxCRDInstances` bounds custom-resource enumeration for one terminating CRD. Persisted finding/action payload is independently capped at 384 KiB, 512 detailed findings, and 256 actions. Exceeding any limit retains bounded evidence plus a count summary, sets `DiagnosisComplete=False`, and removes all recommended actions. A later complete scan can publish actions again.

Namespace labels are obtained through paginated metadata lists. The scanner builds no diagnosis dependency snapshot when there are no deleting targets; otherwise it fetches only Services, EndpointSlices, and controller workloads referenced by relevant webhook and policy configuration rather than retaining full-cluster workload inventories.

## Approval and execution

A `RemediationApproval` spec is immutable and identifies one incident UID plus one current action ID. The executor validates, in fail-closed order:

1. approval and incident UID
2. current incident phase and action identity
3. scanner-owned action evidence deadline, before and after the per-target lock
4. active policy UID and generation
5. policy compilation and approval TTL
6. fixed risk and exact allowlist eligibility
7. target UID and resource-version preconditions
8. API-server dry-run or persisted mutation result

Action IDs deterministically bind action type, target UID, finalizer, target resource version, policy UID, and policy generation. Target changes and policy revisions rotate the action ID even when the operation type is unchanged. A pending approval for an ID removed by incident refresh is marked `Superseded` before any target call; operators must review the refreshed evidence and create a new approval. Running approvals retain their durable action snapshot for idempotent replay.

Approvals against one target are serialized in-process. Replays are idempotent: an already absent finalizer/target records `AlreadySatisfied`. A same-name object with another UID records `TargetReplaced`. Status keeps bounded, sanitized attempts and stable error reasons; it does not copy arbitrary API object bodies.

## Endpoints and observability

Health and readiness are unauthenticated HTTP only inside the pod on 8081. Metrics use controller-runtime HTTPS on 8443 and delegated Kubernetes TokenReview/SubjectAccessReview authorization. The shipped metrics reader permits only non-resource `GET /metrics` and is intentionally unbound.

Metrics use bounded labels only: scanner cycle/list/diagnosis result, policy readiness, incident phase, discovery result, and fixed remediation action/risk/result/dry-run values. Optional ServiceMonitor and PrometheusRule objects live outside required profiles.
