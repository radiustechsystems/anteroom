# Anteroom.
#
# `make check` is what CI runs on every commit and what you should run before
# pushing. `make acceptance` is the end-to-end suite; it needs Docker and takes
# minutes rather than seconds, so it is separate on purpose.

GO ?= go

# What a local build stamps into anteroom_build_info. The release workflow passes
# the tag it published under; `git describe` is the closest local equivalent, and
# it says "-dirty" when the tree is, which is the part worth having.
VCS_REF ?= $(shell git rev-parse HEAD 2>/dev/null)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)

.PHONY: help
help:
	@echo "check              gofmt, vet, unit tests (fast, no Docker)"
	@echo "test               unit tests with the race detector"
	@echo "build              build ./anteroom"
	@echo "image              build the container image"
	@echo "acceptance         tiers 0-1 end to end (needs Docker)"
	@echo "acceptance-browser tier 2 in a real browser (needs Playwright)"
	@echo "example-up         run the reference deployment at localhost:8080"
	@echo "example-down       tear it down"
	@echo "helm-lint          lint the charts in charts/"
	@echo "helm-docs          regenerate each chart's README from its values.yaml"
	@echo "helm-test          evaluate the Kyverno policies offline (needs kyverno CLI)"
	@echo "clean-acceptance   remove containers left by an interrupted run"

.PHONY: check
check: fmt vet test

.PHONY: fmt
fmt:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

.PHONY: vet
vet:
	$(GO) vet ./...
	$(GO) vet -tags e2e ./acceptance/...

.PHONY: test
test:
	$(GO) test -race ./...

.PHONY: build
build:
	$(GO) build -trimpath -ldflags="-s -w" -o anteroom ./cmd/anteroom

# The build args matter: .git is out of the build context, so an image built
# without them cannot say which code it is (Dockerfile, and internal/metrics).
.PHONY: image
image:
	docker build \
		--build-arg VCS_REF=$(VCS_REF) \
		--build-arg VERSION=$(VERSION) \
		-t anteroom:local .

# The tier runs in about two minutes warm. 10m leaves room for cold base-image
# pulls without letting a wedged bring-up sit there until someone notices.
.PHONY: acceptance
acceptance:
	$(GO) test -tags e2e -count=1 -timeout 6m ./acceptance/...

.PHONY: acceptance-browser
acceptance-browser:
	cd acceptance/tier2_browser && npm ci && npm test

.PHONY: example-up
example-up:
	@test -f examples/anteroomized/.env || \
		echo "ANTEROOM_HMAC_KEY=$$(openssl rand -base64 32)" > examples/anteroomized/.env
	docker compose -f examples/anteroomized/compose.yaml up -d --build
	@echo "http://localhost:8080 — loopback is a secure context; a LAN address is not (docs/docker.md)"

.PHONY: example-down
example-down:
	docker compose -f examples/anteroomized/compose.yaml down --volumes

# Chart READMEs are generated: prose lives in README.md.gotmpl, the values
# table in values.yaml's `# --` comments. Edit those, never README.md itself.
# helm-docs: https://github.com/norwoodj/helm-docs
.PHONY: helm-docs
helm-docs:
	helm-docs --chart-search-root charts

.PHONY: helm-lint
helm-lint:
	@for c in charts/*/; do helm lint "$$c" || exit 1; done

# What the policies do, not just that they render: `kyverno apply` evaluates
# each one against a fixture offline and the results are diffed against
# committed expectations. Needs the kyverno CLI as well as helm:
# https://kyverno.io/docs/kyverno-cli/
.PHONY: helm-test
helm-test:
	@for t in charts/*/tests/run.sh; do "$$t" || exit 1; done

.PHONY: clean-acceptance
clean-acceptance:
	@docker ps -a --filter 'name=artest-' -q | xargs -r docker rm -f
	@docker ps -a --filter 'name=artier2-' -q | xargs -r docker rm -f
