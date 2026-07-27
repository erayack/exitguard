SHELL := /usr/bin/env bash

GO ?= go
CONTAINER_TOOL ?= docker
KUBECTL ?= kubectl
IMG ?= exitguard:latest
LOCALBIN ?= $(CURDIR)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
STATICCHECK ?= $(LOCALBIN)/staticcheck
CONTROLLER_TOOLS_VERSION ?= v0.20.1
ENVTEST_VERSION ?= v0.0.0-20260305142021-f9589b9f2b9d
ENVTEST_K8S_VERSION ?= 1.35.0
GOLANGCI_LINT_VERSION ?= v2.12.2
STATICCHECK_VERSION ?= v0.7.0

.PHONY: all
all: build

.PHONY: manifests
manifests: controller-gen
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: test-unit
test-unit: manifests generate fmt vet
	$(GO) test ./... -coverprofile cover.out

.PHONY: test
test: manifests generate fmt vet envtest
	KUBEBUILDER_ASSETS="$$( $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path )" \
		$(GO) test ./... -coverprofile cover.out

.PHONY: build
build: manifests generate fmt vet
	$(GO) build -o bin/exitguard ./cmd

.PHONY: run
run: manifests generate fmt vet
	$(GO) run ./cmd --leader-elect=false --metrics-secure=false

.PHONY: lint
lint: golangci-lint
	$(GOLANGCI_LINT) run

.PHONY: staticcheck
staticcheck: $(STATICCHECK)
	$(STATICCHECK) ./...

.PHONY: docker-build
docker-build:
	$(CONTAINER_TOOL) build -t $(IMG) .

.PHONY: manifests-check
manifests-check:
	$(KUBECTL) kustomize config/default >/dev/null
	$(KUBECTL) kustomize config/remediation >/dev/null
	$(KUBECTL) kustomize config/prometheus/report-only >/dev/null
	$(KUBECTL) kustomize config/prometheus/remediation >/dev/null
	$(KUBECTL) kustomize config/samples >/dev/null

.PHONY: test-e2e
test-e2e:
	K8S_VERSION=$(ENVTEST_K8S_VERSION) PROFILE=remediation ./hack/kind-e2e.sh

.PHONY: perf
perf:
	GO=$(GO) ./hack/perf.sh run

.PHONY: perf-full
perf-full:
	GO=$(GO) ./hack/perf.sh full

.PHONY: perf-profile
perf-profile:
	GO=$(GO) BENCH='$(BENCH)' ./hack/perf.sh profile

.PHONY: perf-profile-alloc
perf-profile-alloc:
	GO=$(GO) BENCH='$(BENCH)' ./hack/perf.sh profile-alloc

.PHONY: perf-compare
perf-compare:
	GO=$(GO) BASE='$(BASE)' ./hack/perf.sh compare

.PHONY: perf-clean
perf-clean:
	GO=$(GO) ./hack/perf.sh clean

.PHONY: deploy
deploy: manifests manifests-check
	$(KUBECTL) apply -k config/default
	$(KUBECTL) -n exitguard-system set image deployment/exitguard-scanner manager=$(IMG)

.PHONY: deploy-remediation
deploy-remediation: manifests manifests-check
	$(KUBECTL) apply -k config/remediation
	$(KUBECTL) -n exitguard-system set image deployment/exitguard-scanner manager=$(IMG)
	$(KUBECTL) -n exitguard-system set image deployment/exitguard-executor manager=$(IMG)

.PHONY: clean
clean:
	rm -rf bin cover.out

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN)
$(CONTROLLER_GEN): | $(LOCALBIN)
	GOBIN=$(LOCALBIN) $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST)
$(ENVTEST): | $(LOCALBIN)
	GOBIN=$(LOCALBIN) $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT)
$(GOLANGCI_LINT): | $(LOCALBIN)
	GOBIN=$(LOCALBIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(STATICCHECK): | $(LOCALBIN)
	GOBIN=$(LOCALBIN) $(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
