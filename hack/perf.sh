#!/usr/bin/env bash
# Copyright 2026 The ExitGuard Authors.
# Licensed under the Apache License, Version 2.0.

set -euo pipefail

GO=${GO:-go}
PERF_COUNT=${PERF_COUNT:-6}
PERF_BENCHTIME=${PERF_BENCHTIME:-1s}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARTIFACT_ROOT=${PERF_ARTIFACT_ROOT:-"$ROOT/.perf"}

usage() {
  cat <<'USAGE'
usage: hack/perf.sh run|full|profile|profile-alloc|compare|clean

Environment/arguments:
  BENCH=<exact benchmark[/subbenchmark]>  required by profile modes
  BASE=<git revision>                    required by compare
  PERF_COUNT=6                           samples per benchmark (minimum 6)
  PERF_BENCHTIME=1s                      Go benchmark duration
USAGE
}

fail() {
  printf 'perf: %s\n' "$*" >&2
  exit 2
}

stamp() {
  date -u '+%Y%m%dT%H%M%SZ'
}

cpu_name() {
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model 2>/dev/null || true
  elif command -v lscpu >/dev/null 2>&1; then
    lscpu 2>/dev/null | awk -F: '/Model name/{sub(/^[[:space:]]+/, "", $2); print $2; exit}'
  fi
}

write_metadata() {
  local worktree=$1 output=$2 mode=$3 command_line=$4 scale=$5
  local dirty=clean
  if [[ -n "$(git -C "$worktree" status --porcelain --untracked-files=normal)" ]]; then
    dirty=dirty
  fi
  {
    printf 'timestamp_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'sha=%s\n' "$(git -C "$worktree" rev-parse HEAD)"
    printf 'worktree=%s\n' "$dirty"
    printf 'go_version=%s\n' "$($GO version)"
    printf 'goos=%s\n' "$(cd "$worktree" && $GO env GOOS)"
    printf 'goarch=%s\n' "$(cd "$worktree" && $GO env GOARCH)"
    printf 'cpu=%s\n' "$(cpu_name)"
    printf 'gomaxprocs=%s\n' "${GOMAXPROCS:-default}"
    printf 'mode=%s\n' "$mode"
    printf 'benchmark_scale=%s\n' "$scale"
    printf 'samples=%s\n' "$PERF_COUNT"
    printf 'benchtime=%s\n' "$PERF_BENCHTIME"
    printf 'command=%s\n' "$command_line"
    printf 'latency_source=local Go benchmark with in-memory stub/fake clients\n'
    printf 'envtest=excluded; existing envtest covers admission validation only and has no reusable reconciliation benchmark fixture\n'
  } >"$output"
}

discovery_policy_default='BenchmarkDiscoverySnapshotBuild/small BenchmarkDiscoverySnapshotBuild/medium BenchmarkDiscoverySnapshotLookup/small BenchmarkDiscoverySnapshotLookup/medium BenchmarkPolicyCompile/small BenchmarkPolicyCompile/medium BenchmarkPolicyMatchWinner/small BenchmarkPolicyMatchWinner/medium'
evidence_bounds_default='BenchmarkEvidenceCollectionSortAndBounds/small_below_bound BenchmarkEvidenceCollectionSortAndBounds/medium_at_bound'
diagnosis_algorithms_default='BenchmarkEvidenceIDHashing/small BenchmarkEvidenceIDHashing/medium BenchmarkEvidenceSortedClone/small BenchmarkEvidenceSortedClone/medium BenchmarkDiagnosisNamespaceComponentStub/small BenchmarkDiagnosisNamespaceComponentStub/medium BenchmarkDiagnosisCRDComponentStub/small BenchmarkDiagnosisCRDComponentStub/medium'
diagnosis_generic_default='BenchmarkDiagnosisGenericComponentStub'
executor_default='BenchmarkExecutorReconcile/ResourceFinalizerMutation BenchmarkExecutorReconcile/ResourceFinalizerDryRun BenchmarkExecutorReconcile/ReplayAlreadySatisfied BenchmarkExecutorReconcile/SupersededAction BenchmarkExecutorReconcile/AlreadySatisfied BenchmarkExecutorReconcile/TargetReplaced BenchmarkExecutorReconcile/ValidationRejected BenchmarkExecutorReconcile/CRDFinalizerMutation BenchmarkExecutorReconcile/NamespaceFinalize'
scanner_cycle_default='BenchmarkScannerCycle/StubSmall BenchmarkScannerCycle/StubMedium'
scanner_lifecycle_default='BenchmarkScannerLifecycle'

full_manifest="$discovery_policy_default BenchmarkDiscoverySnapshotBuild/large BenchmarkDiscoverySnapshotLookup/large BenchmarkPolicyCompile/large BenchmarkPolicyMatchWinner/large $evidence_bounds_default BenchmarkEvidenceCollectionSortAndBounds/large_above_bound $diagnosis_algorithms_default BenchmarkEvidenceIDHashing/large BenchmarkEvidenceSortedClone/large BenchmarkDiagnosisNamespaceComponentStub/large_bound BenchmarkDiagnosisCRDComponentStub/large_bound $diagnosis_generic_default $executor_default $scanner_cycle_default BenchmarkScannerCycle/StubFullLarge $scanner_lifecycle_default"

validate_benchmark_output() {
  local output=$1 expected_samples=$2 manifest=$3
  awk -v expected_samples="$expected_samples" -v manifest="$manifest" '
    BEGIN {
      expected_total=split(manifest, names, /[[:space:]]+/)
      for (i=1; i<=expected_total; i++) {
        if (names[i] != "") expected[names[i]]=1
      }
    }
    /^Benchmark/ {
      name=$1
      sub(/-[0-9]+$/, "", name)
      observed[name]++
    }
    END {
      failed=0
      expected_count=0
      for (name in expected) {
        expected_count++
        if (observed[name] != expected_samples) {
          printf "perf: benchmark %s produced %d samples; expected %d\n", name, observed[name]+0, expected_samples > "/dev/stderr"
          failed=1
        }
      }
      for (name in observed) {
        if (!(name in expected)) {
          printf "perf: unexpected benchmark sample %s\n", name > "/dev/stderr"
          failed=1
        }
      }
      if (expected_count == 0) {
        print "perf: benchmark manifest is empty" > "/dev/stderr"
        failed=1
      }
      exit failed
    }
  ' "$output"
}

run_go_bench() {
  local worktree=$1 raw=$2 regex=$3 manifest=$4
  shift 4
  local invocation
  invocation=$(mktemp "${TMPDIR:-/tmp}/exitguard-bench.XXXXXX")
  local -a command=("$GO" test "$@" -run '^$' -bench "$regex" -benchmem -benchtime "$PERF_BENCHTIME" -count "$PERF_COUNT")
  printf '+ (cd %q &&' "$worktree" | tee -a "$raw"
  printf ' %q' "${command[@]}" | tee -a "$raw"
  printf ')\n' | tee -a "$raw"
  if ! (cd "$worktree" && "${command[@]}") 2>&1 | tee "$invocation" | tee -a "$raw"; then
    rm -f "$invocation"
    return 1
  fi
  if ! validate_benchmark_output "$invocation" "$PERF_COUNT" "$manifest"; then
    rm -f "$invocation"
    fail 'benchmark output did not match the required manifest'
  fi
  rm -f "$invocation"
}

run_default_suite() {
  local worktree=$1 raw=$2
  : >"$raw"
  run_go_bench "$worktree" "$raw" '^(BenchmarkDiscoverySnapshotBuild|BenchmarkDiscoverySnapshotLookup|BenchmarkPolicyCompile|BenchmarkPolicyMatchWinner)$/^(small|medium)$' "$discovery_policy_default" ./internal/discovery ./internal/policy
  run_go_bench "$worktree" "$raw" '^(BenchmarkEvidenceCollectionSortAndBounds)$/^(small_below_bound|medium_at_bound)$' "$evidence_bounds_default" ./internal/diagnosis
  run_go_bench "$worktree" "$raw" '^(BenchmarkEvidenceIDHashing|BenchmarkEvidenceSortedClone|BenchmarkDiagnosisNamespaceComponentStub|BenchmarkDiagnosisCRDComponentStub)$/^(small|medium)$' "$diagnosis_algorithms_default" ./internal/diagnosis
  run_go_bench "$worktree" "$raw" '^BenchmarkDiagnosisGenericComponentStub$' "$diagnosis_generic_default" ./internal/diagnosis
  run_go_bench "$worktree" "$raw" '^BenchmarkExecutorReconcile$' "$executor_default" ./internal/executor
  run_go_bench "$worktree" "$raw" '^BenchmarkScannerCycle$/^(StubSmall|StubMedium)$' "$scanner_cycle_default" ./internal/scanner
  run_go_bench "$worktree" "$raw" '^BenchmarkScannerLifecycle$' "$scanner_lifecycle_default" ./internal/scanner
}

run_full_suite() {
  local worktree=$1 raw=$2
  : >"$raw"
  run_go_bench "$worktree" "$raw" '^Benchmark' "$full_manifest" ./internal/...
}

fallback_summary() {
  local raw=$1 summary=$2
  {
    printf 'benchstat unavailable; raw samples and fallback statistics follow\n\n'
    cat "$raw"
    printf '\nmedian and range by benchmark (same-machine samples):\n'
    awk '
      /^Benchmark/ {
        benchmark=$1
        for (i=2; i<=NF; i++) {
          if ($i=="ns/op" || $i=="B/op" || $i=="allocs/op") {
            key=benchmark "|" $i
            count[key]++
            values[key SUBSEP count[key]]=$(i-1)+0
          }
        }
      }
      END {
        for (key in count) {
          n=count[key]
          for (i=1; i<=n; i++) sorted[i]=values[key SUBSEP i]
          for (i=2; i<=n; i++) {
            value=sorted[i]; j=i-1
            while (j>=1 && sorted[j]>value) { sorted[j+1]=sorted[j]; j-- }
            sorted[j+1]=value
          }
          if (n%2) median=sorted[(n+1)/2]
          else median=(sorted[n/2]+sorted[n/2+1])/2
          split(key, parts, "|")
          printf "%s %s samples=%d median=%.3f range=[%.3f,%.3f]\n", parts[1], parts[2], n, median, sorted[1], sorted[n]
          for (i=1; i<=n; i++) delete sorted[i]
        }
      }
    ' "$raw" | sort
  } >"$summary"
}

summarize() {
  local raw=$1 summary=$2
  if command -v benchstat >/dev/null 2>&1; then
    benchstat "$raw" >"$summary"
  else
    fallback_summary "$raw" "$summary"
  fi
}

require_samples() {
  [[ "$PERF_COUNT" =~ ^[0-9]+$ ]] || fail "PERF_COUNT must be an integer"
  (( PERF_COUNT >= 6 )) || fail "PERF_COUNT must be at least 6 for run/full/compare"
}

run_mode() {
  local mode=$1
  require_samples
  local output
  output="$ARTIFACT_ROOT/$(stamp)-${mode}-$$"
  mkdir -p "$output"
  local raw="$output/bench.txt"
  local command_line
  if [[ "$mode" == full ]]; then
    command_line="go test ./internal/... -run '^$' -bench '^Benchmark' -benchmem -benchtime $PERF_BENCHTIME -count $PERF_COUNT"
    write_metadata "$ROOT" "$output/environment.txt" "$mode" "$command_line" 'all scales, including names containing Full or large'
    run_full_suite "$ROOT" "$raw"
  else
    command_line="hack/perf.sh run (package-specific anchored default benchmark regexes), -run '^$' -benchmem -benchtime $PERF_BENCHTIME -count $PERF_COUNT"
    write_metadata "$ROOT" "$output/environment.txt" "$mode" "$command_line" 'small and medium; full-only/large scales excluded'
    run_default_suite "$ROOT" "$raw"
  fi
  summarize "$raw" "$output/summary.txt"
  printf '%s\n' "$output"
}

regex_escape() {
  printf '%s' "$1" | sed 's/[][\\.^$*+?(){}|]/\\&/g'
}

exact_bench_regex() {
  local value=$1 part result=''
  local -a parts
  IFS='/' read -r -a parts <<<"$value"
  for part in "${parts[@]}"; do
    [[ -n "$part" ]] || fail "BENCH contains an empty path component"
    if [[ -n "$result" ]]; then result+='/'; fi
    result+="^$(regex_escape "$part")\$"
  done
  printf '%s' "$result"
}

benchmark_package() {
  case "$1" in
    BenchmarkDiscovery*) printf './internal/discovery' ;;
    BenchmarkPolicy*) printf './internal/policy' ;;
    BenchmarkEvidence*|BenchmarkDiagnosis*) printf './internal/diagnosis' ;;
    BenchmarkExecutor*) printf './internal/executor' ;;
    BenchmarkScanner*) printf './internal/scanner' ;;
    *) fail "cannot determine package for exact benchmark '$1'" ;;
  esac
}

require_known_profile_benchmark() {
  local requested=$1 candidate
  for candidate in $full_manifest; do
    if [[ "$candidate" == "$requested" ]]; then
      return
    fi
  done
  fail "BENCH must name exactly one benchmark from the explicit manifest; unknown or incomplete name '$requested'"
}

reject_unsafe_profile() {
  case "$1" in
    BenchmarkExecutorReconcile|BenchmarkExecutorReconcile/*)
      fail 'BenchmarkExecutorReconcile cannot be profiled: per-iteration fake-client fixture construction would contaminate process-wide profiles'
      ;;
    BenchmarkScannerLifecycle)
      fail 'BenchmarkScannerLifecycle cannot be profiled: per-iteration lifecycle fixture construction would contaminate process-wide profiles'
      ;;
  esac
}

run_profile_bench() {
  local package=$1 regex=$2 bench=$3 output=$4
  shift 4
  (cd "$ROOT" && "$GO" test "$package" -run '^$' -bench "$regex" -benchmem -benchtime "$PERF_BENCHTIME" -count 1 "$@") 2>&1 | tee "$output"
  validate_benchmark_output "$output" 1 "$bench" || fail 'profile output did not contain exactly one sample for BENCH'
}

profile_mode() {
  local resolution=$1
  local bench=${BENCH:-}
  [[ -n "$bench" ]] || fail 'BENCH=<exact benchmark[/subbenchmark]> is required'
  require_known_profile_benchmark "$bench"
  reject_unsafe_profile "$bench"
  local top=${bench%%/*}
  local package regex output
  package=$(benchmark_package "$top")
  regex=$(exact_bench_regex "$bench")
  output="$ARTIFACT_ROOT/$(stamp)-profile-$(printf '%s' "$bench" | tr '/ ' '__')-$$"
  mkdir -p "$output"
  write_metadata "$ROOT" "$output/environment.txt" "profile-$resolution" "go test $package -run '^$' -bench '$regex' -benchmem -count 1" "exact: $bench"

  if [[ "$resolution" == standard ]]; then
    run_profile_bench "$package" "$regex" "$bench" "$output/cpu.txt" -o "$output/cpu.test" -cpuprofile "$output/cpu.pprof"
    run_profile_bench "$package" "$regex" "$bench" "$output/allocs.txt" -o "$output/allocs.test" -memprofile "$output/allocs.pprof"
  else
    run_profile_bench "$package" "$regex" "$bench" "$output/allocs-hires.txt" -o "$output/allocs-hires.test" -memprofile "$output/allocs-hires.pprof" -memprofilerate=1
  fi
  printf '%s\n' "$output"
}

compare_mode() {
  require_samples
  local base=${BASE:-}
  [[ -n "$base" ]] || fail 'BASE=<git revision> is required'
  git -C "$ROOT" rev-parse --verify "$base^{commit}" >/dev/null || fail "unknown base revision '$base'"
  local output
  output="$ARTIFACT_ROOT/$(stamp)-compare-$$"
  mkdir -p "$output"
  local temporary base_tree candidate_tree
  temporary=$(mktemp -d "${TMPDIR:-/tmp}/exitguard-perf.XXXXXX")
  base_tree="$temporary/base"
  candidate_tree="$temporary/candidate"
  cleanup_compare() {
    git -C "$ROOT" worktree remove --force "$base_tree" >/dev/null 2>&1 || true
    git -C "$ROOT" worktree remove --force "$candidate_tree" >/dev/null 2>&1 || true
    rm -rf "$temporary"
  }
  trap cleanup_compare EXIT INT TERM
  git -C "$ROOT" worktree add --detach "$base_tree" "$base" >/dev/null
  git -C "$ROOT" worktree add --detach "$candidate_tree" HEAD >/dev/null
  write_metadata "$base_tree" "$output/base-environment.txt" compare "isolated default suite, -run '^$' -benchmem -count $PERF_COUNT" 'small and medium'
  write_metadata "$candidate_tree" "$output/candidate-environment.txt" compare "isolated default suite, -run '^$' -benchmem -count $PERF_COUNT" 'small and medium'
  run_default_suite "$base_tree" "$output/base.txt"
  run_default_suite "$candidate_tree" "$output/candidate.txt"
  local base_names candidate_names
  base_names=$(awk '/^Benchmark/ { name=$1; sub(/-[0-9]+$/, "", name); print name }' "$output/base.txt" | sort -u)
  candidate_names=$(awk '/^Benchmark/ { name=$1; sub(/-[0-9]+$/, "", name); print name }' "$output/candidate.txt" | sort -u)
  [[ -n "$base_names" && "$base_names" == "$candidate_names" ]] || fail 'baseline and candidate benchmark sets are empty or asymmetric'
  if command -v benchstat >/dev/null 2>&1; then
    benchstat "$output/base.txt" "$output/candidate.txt" >"$output/comparison.txt"
  else
    fallback_summary "$output/base.txt" "$output/base-summary.txt"
    fallback_summary "$output/candidate.txt" "$output/candidate-summary.txt"
    {
      printf 'benchstat unavailable; compare the baseline and candidate fallback medians/ranges below.\n\nBASELINE\n'
      cat "$output/base-summary.txt"
      printf '\nCANDIDATE\n'
      cat "$output/candidate-summary.txt"
    } >"$output/comparison.txt"
  fi
  cleanup_compare
  trap - EXIT INT TERM
  printf '%s\n' "$output"
}

mode=${1:-}
case "$mode" in
  run) run_mode default ;;
  full) run_mode full ;;
  profile) profile_mode standard ;;
  profile-alloc) profile_mode high-resolution-allocation ;;
  compare) compare_mode ;;
  clean) rm -rf "$ARTIFACT_ROOT" ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
