# Performance harness

ExitGuard's performance harness detects regressions in application algorithms and observable operation counts. It is not a capacity test. All current component and reconciliation benchmarks use deterministic in-memory fixtures, stubs, or Kubernetes fake clients.

## Coverage

| Area | Benchmarks and scales | What is exercised | Intentional exclusions |
| --- | --- | --- | --- |
| Discovery | `BenchmarkDiscoverySnapshotBuild`, `BenchmarkDiscoverySnapshotLookup`; small/medium/large | preferred and alternate version construction, ordering, resolution hits and misses | discovery HTTP latency and partial server responses |
| Policy | `BenchmarkPolicyCompile`, `BenchmarkPolicyMatchWinner`; small/medium/large | compile, resource resolution, selectors, matching, priority/tie winner selection | admission and API-server storage latency |
| Evidence algorithms | `BenchmarkEvidenceCollectionSortAndBounds`, `BenchmarkEvidenceIDHashing`, `BenchmarkEvidenceSortedClone`; below/at/above bounds and small/medium/large | deterministic sorting, truncation, overflow evidence, IDs/hashes, detached clones | object serialization and API-server object limits beyond the enforced in-process bounds |
| Diagnosis | `BenchmarkDiagnosisGenericComponentStub`; Namespace and CRD component small/medium/`large_bound` | target GETs, generic finalizers, namespace inventory pagination, CRD instance pagination, bounded evidence and exact operation counts | live discovery, network latency, admission, and etcd |
| Scanner steady cycle | `BenchmarkScannerCycle/StubSmall` (120 objects), `StubMedium` (1,600), `StubFullLarge` (10,000) | discovery snapshot use, primed policy cache, multiple policies/selectors, namespace inventory, namespaced and cluster-scoped resources, ordinary/deleting objects, pagination, bounded resource/diagnosis workers, diagnosis, incident/metric reads, exact no-write steady state | `Coordinator.Start` ticker scheduling; `RunCycle` contains the complete work without nondeterministic sleeps |
| Incident lifecycle | `BenchmarkScannerLifecycle` (small) | cold policy statuses, incident create/status update, failed-to-active transition, stale-target resolution, retention delete, metrics relist, exact writes/deletes | controller-runtime queue and API-server latency |
| Executor | `BenchmarkExecutorReconcile/<scenario>` | full validation, owner/status writes, immutable action snapshot, replay, supersession, already-satisfied, target replacement, rejection, dry-run, resource/CRD finalizer patch, Namespace finalize, exact typed/dynamic/status operations | controller queueing and real patch/finalize latency |

Executor scenarios are `ResourceFinalizerMutation`, `ResourceFinalizerDryRun`, `ReplayAlreadySatisfied`, `SupersededAction`, `AlreadySatisfied`, `TargetReplaced`, `ValidationRejected`, `CRDFinalizerMutation`, and `NamespaceFinalize`.

The default suite includes small and medium scales and all executor scenarios. `make perf-full` additionally includes names containing `large`, `large_bound`, or `FullLarge`. Scanner concurrency uses fixed worker bounds; the harness does not tune them.

## Commands and artifacts

All benchmark invocations use `-run '^$'` and `-benchmem`. A default or full run records at least six same-machine samples.

```sh
make perf
make perf-full

# BENCH is one exact benchmark or benchmark/subbenchmark name.
make perf-profile BENCH='BenchmarkExecutorReconcile/AlreadySatisfied'
make perf-profile-alloc BENCH='BenchmarkEvidenceIDHashing/small'

make perf-compare BASE='origin/main'
make perf-clean
```

Artifacts are written under ignored `.perf/<UTC timestamp>-<mode>-<pid>/`:

- `environment.txt`: Git SHA/dirty state, timestamp, Go version, GOOS/GOARCH, CPU, GOMAXPROCS, command, sample count, scale, and latency-source labels.
- `bench.txt`: every raw sample. `summary.txt` uses `benchstat` when installed; otherwise it includes the raw samples and median/range for `ns/op`, `B/op`, and `allocs/op`.
- profile directories: separate text output, test binaries, `cpu.pprof`, `allocs.pprof`, or `allocs-hires.pprof`.
- comparison directories: isolated base/candidate metadata and samples plus `comparison.txt`.

`make perf-profile` executes the exact benchmark twice: once for CPU and once for the standard allocation profile. CPU profiling never enables `-memprofilerate=1`. `make perf-profile-alloc` is a separate, slower high-resolution allocation run with that setting. Exact names are escaped and anchored component by component, including subbenchmark path components.

Comparison creates detached temporary worktrees for `BASE` and `HEAD`, places artifacts outside both, and removes the worktrees afterward. It compares committed revisions; uncommitted working-tree changes are deliberately not copied into the candidate. Every invocation is checked against the suite's explicit benchmark manifest and required sample count. Comparison also requires identical, non-empty benchmark sets, so missing, renamed, or asymmetric benchmarks stop the command before a summary is produced. Failed benchmarks, operation mismatches, or failed summaries also stop the command.

The tagged envtest suite now provides real-API correctness coverage for CRD admission/defaulting, scanner persistence and incident creation, and executor dry-run/status/mutation behavior. It contains no benchmarks: envtest performance coverage remains intentionally excluded. If added later, keep it in a separate lane and label and store it as a distinct latency source; never compare its latency directly with fake/stub or live-cluster results.

## Profiles

Use the test binary stored beside a profile so symbolization matches exactly:

```sh
go tool pprof -top .perf/<profile-dir>/cpu.test .perf/<profile-dir>/cpu.pprof
go tool pprof -http=:0 .perf/<profile-dir>/cpu.test .perf/<profile-dir>/cpu.pprof

go tool pprof -top -alloc_space .perf/<profile-dir>/allocs.test .perf/<profile-dir>/allocs.pprof
go tool pprof -top -alloc_objects .perf/<profile-dir>/allocs-hires.test .perf/<profile-dir>/allocs-hires.pprof
```

Profiling changes execution and allocation behavior. Do not compare profiled numbers with ordinary benchmark samples. Profiles are process-wide and are not limited by `b.StopTimer`; the harness therefore rejects `BenchmarkExecutorReconcile` and `BenchmarkScannerLifecycle`, whose per-iteration fake-client fixture construction would otherwise dominate or contaminate profiles. Use ordinary repeated samples and operation metrics for those lifecycle benchmarks. Profile modes also require the command to produce exactly one sample for the exact requested benchmark name.

## Interpretation limits

Use repeated same-machine results to detect changes in algorithms, allocations, and exact operation counts. Custom metrics such as `api_operations/cycle`, `writes/reconcile`, pages, retries, and mismatches describe calls observed by the harness; they are not durations.

Do **not** present these results as Kubernetes API latency, live-cluster throughput, or production capacity. Stub/fake clients omit transport, authentication, admission, API priority and fairness, serialization boundaries, etcd, controllers, and cluster contention. Fixture construction is excluded from timed regions where documented. Go GC, scheduler state, CPU frequency, background load, fake-client internals, benchmark calibration, and profilers can still distort `ns/op`, `B/op`, and allocations. Envtest, fake/stub, and production measurements are distinct latency sources.

## Extending benchmarks

1. Put deterministic fixture construction and cache priming outside the timer; reset counters immediately before timing.
2. Use fixed timestamps, UIDs, resource versions, page sizes, and worker bounds. Do not add sleeps or benchmark-only production paths.
3. Make output observable, verify externally visible state after timing, and fail on any mismatch.
4. Use `ReportAllocs` and shared `internal/perftest` counters for every production-facing operation used by the path. Check exact expected counts; report retries, writes, and mismatches even when zero.
5. Give expensive cases a `large`, `large_bound`, or `FullLarge` name and add them only to the full suite. Update `hack/perf.sh` default regexes and this matrix when adding a top-level benchmark.
6. Keep fake/stub/envtest/live labels explicit. Never optimize production code as part of a benchmark-only change.
