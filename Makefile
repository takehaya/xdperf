# cf. based https://gist.github.com/thomaspoignant/5b72d579bd5f311904d973652180c705
GOCMD=go
TINYGOCMD=tinygo
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
VERSION := 0.0.1
GIT_HASH=$(git rev-parse --short HEAD)
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
DIFF_FROM_BRANCH_NAME ?= origin/main

ENTRY_POINT_DIR=cmd
ENTRY_POINT_DIR_PLUGINS=plugins
TARGETS=$(notdir $(wildcard $(ENTRY_POINT_DIR)/*))
PLUGIN_TARGETS := $(notdir $(shell find $(ENTRY_POINT_DIR_PLUGINS) -mindepth 1 -maxdepth 1 -type d))

GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: all
all: help

## Build:
.PHONY: build, make_outdir, clean
build: make_outdir build-targets build-plugins ## Build your project and put the output binary in out/bin/
make_outdir:
	mkdir -p out/bin

.PHONY: $(TARGETS)
.PHONY: build-targets
build-targets: $(TARGETS) ## Build main targets
$(TARGETS):
	$(GOCMD) build -o out/bin/$@ ./cmd/$@/

.PHONY: build-plugins
build-plugins: $(PLUGIN_TARGETS) ## Build TinyGo plugins
%.tinygo:
	@echo "Building TinyGo plugin: $@"
	cd plugins/$@ && $(TINYGOCMD) build -scheduler=none -target=wasip1 -buildmode=c-shared -o ../../out/bin/$@.wasm .
%.go:
	@echo "Building Go plugin: $@"
	cd plugins/$@ && GOOS=wasip1 GOARCH=wasm $(GOCMD) build -buildmode=c-shared -o ../../out/bin/$@.wasm .

.PHONY: goreleaser
goreleaser: ## build with goreleaser
	goreleaser release --snapshot --clean

clean: ## Remove build related file
	rm -fr ./out/bin

## Test:
.PHONY: test-runnable
test-runnable: ## check no panic at init()
	@for file in $(TARGETS); do \
		echo [test] $$file; \
		./out/bin/$$file -v; \
		if [ $$? -ne 0 ]; then \
			echo "Failed to run $$file"; \
			exit 1; \
		fi; \
	done

.PHONY: test
test: ## Run the tests of the project
	$(GOTEST) -v -exec sudo -race ./... $(OUTPUT_OPTIONS)

.PHONY: test-bpf
test-bpf: ## Run BPF program load tests (requires root/CAP_BPF)
	$(GOTEST) -v -exec sudo ./pkg/coreelf/ -run TestBpf

## Golang:
.PHONY: bpf-gen

bpf-gen: export BPF_CLANG := $(CLANG)
bpf-gen: export BPF_CFLAGS := $(CFLAGS) $(CEXTRA_FLAGS)
bpf-gen: ## generate ebpf code and object files
	docker build --build-arg BPF_CLANG=${BPF_CLANG} --build-arg BPF_CFLAGS="${BPF_CFLAGS}" . --output ./pkg -f Dockerfile.bpf

## Lint:
.PHONY: install-lint-tools
install-lint-tools: ## install lint tools
	./scripts/install_lint_tools.sh

.PHONY: lint
lint: ## Run lefthook, fmt and lint for this project.
	lefthook run pre-commit --all-files

.PHONY: lint-ci
lint-ci: ## Run lefthook for CI
	FILES="$$(git diff --name-only $(DIFF_FROM_BRANCH_NAME) HEAD | tr '\n' ' ')"; \
	if [ -n "$$FILES" ]; then \
		lefthook run pre-commit --file $$FILES; \
	fi

.PHONY: nilaway
nilaway: ## Run nil check lint
	nilaway -fix -include-pkgs="$(PACKAGE)" \
		-test=false \
		-exclude-errors-in-files="mock_" \
		./...

## tools and pkg install:
.PHONY: install-dev-pkg
install-dev-pkg: ## install mise.toml
	mise install -y

.PHONY: install-build-tools
install-build-tools: ## install build tools
	./scripts/install_build_tools.sh

.PHONY: install-dev-tools
install-dev-tools: ## install development tools
	./scripts/install_dev_tools.sh

## Env:
.PHONY: remove-ebpfmap show-trace_pipe
remove-ebpfmap: ## remove all ebpf maps
	sudo rm -rf /sys/fs/bpf/*

show-trace_pipe: ## show trace_pipe
	sudo cat /sys/kernel/debug/tracing/trace_pipe

## Examples:
.PHONY: examples
examples: build ## Run veth-based end-to-end example scenarios (requires sudo)
	sudo -E ./examples/run_all.sh

## VM Lab:
.PHONY: vmlab-image vmlab-up vmlab-demo vmlab-down vmlab-clean
VMLAB := ./scripts/vmlab/vmlab.sh
vmlab-image: ## Fetch base cloud image for the VM-to-VM lab (first run only)
	$(VMLAB) image

vmlab-up: build ## Boot the 2-VM (tx/rx) back-to-back lab
	$(VMLAB) up

vmlab-demo: ## Run send/recv demo and print real NIC/recv counters
	$(VMLAB) demo

vmlab-down: ## Stop the VM-to-VM lab
	$(VMLAB) down

vmlab-clean: ## Remove lab overlays/seeds/logs (keeps base image)
	$(VMLAB) clean

## Help:
.PHONY: show-buildtags
show-buildtags: ## Show build tags
	@grep -r 'go:build' ./ 2>/dev/null \
		| awk -e '/[\.]go:/' \
		| cut -d ' ' -f 2- \
		| sort -u

.PHONY: godoc
godoc: ## Start Go Document Sedrver
	@echo "Running godoc..."
	@echo "  - GODOC_HOST='$${GODOC_HOST:-localhost}'"
	@echo open http://$${GODOC_HOST:-localhost}:8080/pkg/
	@godoc -http $${GODOC_HOST:-localhost}:8080

.PHONY: help
help: ## Show this help.
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) { \
			printf "    ${YELLOW}%-30s${GREEN}%s${RESET}\n", $$1, $$2 \
		} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)
