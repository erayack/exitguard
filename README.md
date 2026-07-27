# ExitGuard

**ExitGuard** finds Kubernetes objects stuck in deletion, records sanitized evidence, and remediates finalizers only when a human explicitly approves, never automatically.

Supported Kubernetes releases: **1.33–1.35**. Routine CI runs Go tests, formatting, vet, and lint checks; deployment E2E remains available through `make test-e2e` with an optional `K8S_VERSION`.

## What you get

- **Diagnosis:** policies match terminating objects; incidents capture findings and recommended actions
- **Human gate:** each remediation requires an immutable approval (start with dry-run)
- **Least privilege:** report-only by default; remediation is an opt-in profile with a separate executor identity

## Install

```sh
# Report-only (default): diagnose and open incidents
make deploy IMG=registry.example/exitguard:v0.1.0

# Remediation: add the approval executor (after reviewing RBAC)
make deploy-remediation IMG=registry.example/exitguard:v0.1.0
```

Build the image first with `make docker-build IMG=…`, then push via your usual release process.

## How it works

1. Create a `TerminationPolicy` (see `config/samples/`).
2. ExitGuard opens a `DeletionIncident` when a matching object exceeds `terminationAge`.
3. Review the evidence, then create a `RemediationApproval` for one action; prefer `dryRun: true` first.
4. With the remediation profile installed, the executor rechecks every precondition and applies exactly that action.

## Docs

| | |
| --- | --- |
| [Architecture](docs/architecture.md) | Controllers, CRDs, and safety model |
| [Operations](docs/operations.md) | Day-2 runbooks and recovery |
| [Security](SECURITY.md) | Privilege model and disclosure |

## Develop

```sh
make test-unit    # unit tests
make test         # envtest
make test-e2e     # Kind E2E (report-only + remediation)
make build        # bin/exitguard
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
