# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it privately to the repository owner with the affected version, reproduction conditions, and impact. Do not include live credentials, Secret values, or arbitrary resource bodies.

## Privilege model

The default report-only profile installs only the scanner. It has broad cluster GET/LIST for discovery and metadata diagnosis, concrete watches, ownership of policy status and incidents, and no wildcard patch, approval-status, or namespace-finalize grant.

The remediation profile atomically adds a separate executor identity. Its wildcard-resource target GET/PATCH and `namespaces/finalize` access are high impact. The target rule is limited to explicitly listed built-in and CRD API groups; it excludes the operator, RBAC, admission, and API aggregation groups. It has no wildcard LIST or DELETE grant and no policy/incident status write grant. Because Kubernetes RBAC wildcard resources include subresources within each listed group, the target PATCH rule remains broader than the executor's code path; treat compromise of the executor service account as cluster-impacting. Admission and audit policy should provide environment-specific defense in depth. Custom API target grants are an explicit environment responsibility.

Metrics use HTTPS with controller-runtime delegated authentication and authorization. The included `exitguard-metrics-reader` grants only `GET /metrics` and has no binding. Health probes use a separate pod-local HTTP port and expose no metrics.

## Approval security

There is no automatic remediation mode. Creating an immutable `RemediationApproval` is the authorization signal inside the operator. Restrict approval creation separately from policy editing and incident viewing. The authoritative approver identity is the authenticated user in Kubernetes audit records; the API intentionally does not accept a caller-supplied identity field.

The executor rechecks incident UID, target UID, action ID, policy UID/generation, fixed risk, exact finalizer allowlist, TTL, and resource version. Dry-run uses the API server's dry-run option. Same-name target recreation fails closed. Attempt messages are bounded and sanitized, and metrics do not include resource identity or error text.

Policy cannot lower built-in risk: ordinary finalizer removal is Medium, protective and CRD cleanup removal is High, and namespace force-finalization is Critical. Finalizer wildcards and implicit allowlists are not supported.

## Irreversible risk

Finalizer removal can bypass a controller's cleanup contract and leak infrastructure or data. CRD cleanup-finalizer removal can orphan stored instances. Namespace force-finalization can make remaining objects inaccessible. These actions have no automatic rollback. Review current evidence, recover the responsible controller when possible, inventory external assets, run a dry-run approval, and retain Kubernetes audit records before persistent execution.

## Supported versions

Security fixes target the latest release. The v1 compatibility range is Kubernetes 1.33–1.35. Routine CI runs Go tests and static checks; maintainers run the Kind deployment E2E suite against the intended Kubernetes version before a release.
