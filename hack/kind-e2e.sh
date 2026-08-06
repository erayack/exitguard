#!/usr/bin/env bash
set -euo pipefail

K8S_VERSION="${K8S_VERSION:-1.35.0}"
PROFILE="${PROFILE:-remediation}"
CLUSTER_NAME="${CLUSTER_NAME:-exitguard-e2e-${K8S_VERSION//./-}}"
IMAGE="${IMG:-exitguard:e2e}"
KIND_NODE_IMAGE="kindest/node:v${K8S_VERSION}"
KUBECONFIG_FILE="$(mktemp)"

cleanup() {
  status=$?
  if [[ "${KEEP_CLUSTER:-false}" != "true" ]]; then
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
    rm -f "${KUBECONFIG_FILE}"
  else
    printf 'cluster retained: %s (KUBECONFIG=%s)\n' "${CLUSTER_NAME}" "${KUBECONFIG_FILE}" >&2
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

case "${PROFILE}" in
  default|remediation) ;;
  *) printf 'PROFILE must be default or remediation, got %s\n' "${PROFILE}" >&2; exit 2 ;;
esac

for command in docker kind kubectl go; do
  command -v "${command}" >/dev/null || { printf 'required command not found: %s\n' "${command}" >&2; exit 1; }
done

configure_scanner() {
  kubectl -n exitguard-system set image deployment/exitguard-scanner manager="${IMAGE}"
  kubectl -n exitguard-system patch deployment exitguard-scanner --type=json \
    -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--scan-interval=2s"},{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--discovery-refresh-interval=5s"}]'
  kubectl -n exitguard-system rollout status deployment/exitguard-scanner --timeout=180s
}

docker build -t "${IMAGE}" .
kind create cluster --name "${CLUSTER_NAME}" --image "${KIND_NODE_IMAGE}" --kubeconfig "${KUBECONFIG_FILE}" --wait 120s
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"
export KUBECONFIG="${KUBECONFIG_FILE}"

kubectl apply -k config/default
configure_scanner
E2E_PHASE=report-only go test ./test/e2e -count=1 -timeout=5m

if [[ "${PROFILE}" == "remediation" ]]; then
  kubectl apply -k config/remediation
  configure_scanner
  kubectl -n exitguard-system set image deployment/exitguard-executor manager="${IMAGE}"
  kubectl -n exitguard-system rollout status deployment/exitguard-executor --timeout=180s
  E2E_PHASE=remediation go test ./test/e2e -count=1 -timeout=20m
fi
