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

# Where `make dist` puts release archives, and every platform one is built for.
#
# This list is the release's platform policy, and it lives here rather than in
# the workflow because the workflow runs `make dist` — a list kept in two places
# is a list that will differ, and the way you find out is a release that quietly
# stopped shipping an architecture.
#
# Each entry is a decision:
#
#   linux/amd64, linux/arm64  the two the container image publishes. A binary
#                             release narrower than the image would be a
#                             promise the image already keeps.
#   linux/armv7               the small edge box — a Pi or a cheap ARM VPS —
#                             which is exactly where a self-hosted gate in
#                             front of a personal site tends to run.
#   darwin/amd64, darwin/arm64  a laptop running the gate in front of a
#                             development server, both Mac generations.
#   windows/amd64             a gate in front of IIS or a Windows-hosted app.
#   freebsd/amd64             an edge proxy host is one of the last places
#                             FreeBSD is still routinely chosen.
#
# armv7 is spelled out because GOARCH alone does not say it: `GOARCH=arm`
# without `GOARM` builds for ARMv6, which runs on a Pi but leaves the hard-float
# instructions of every ARM board made this decade unused.
DIST ?= dist
DIST_PLATFORMS ?= \
	linux/amd64 \
	linux/arm64 \
	linux/armv7 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	freebsd/amd64

# What travels with the binary. A gate with no config file cannot start —
# `upstream` has no default — so the example is not a courtesy, it is the
# difference between an archive you can run and one you have to go looking for
# the other half of.
DIST_EXTRA = README.md LICENSE THIRD_PARTY_NOTICES.md anteroom.example.toml

# GNU coreutils on Linux, BSD/macOS spelling otherwise. The checksum file is the
# thing a downloader actually verifies against, so it has to be producible on
# the machine of whoever is checking, not only on the release runner.
SHA256 ?= $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum -a 256)

.PHONY: help
help:
	@echo "check              gofmt, vet, unit tests (fast, no Docker)"
	@echo "test               unit tests with the race detector"
	@echo "build              build ./anteroom"
	@echo "dist               cross-compile release archives into dist/"
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

# Release archives, one per DIST_PLATFORMS entry, plus a SHA256SUMS covering
# them. This is what the release workflow runs; running it by hand produces the
# same tree, which is the point — the artifacts people download are not built by
# a recipe that only exists inside a CI file.
#
# CGO_ENABLED=0 for the same reason the image sets it: a static binary that does
# not need the glibc of the machine that built it. That also makes every one of
# these a genuine cross-compile from one runner rather than a build matrix.
#
# The two -X paths come from `go list -m` rather than being written out, exactly
# as in the Dockerfile and for the same reason: a wrong -X path is not a build
# error. The linker drops an override it cannot resolve without a word, and the
# binary then reports the toolchain's guesses while looking stamped.
#
# VERSION defaults to `git describe`, so a local `make dist` names its archives
# after the tree it built and says `-dirty` when that tree was. The workflow
# passes the tag.
.PHONY: dist
dist:
	@# Only the Windows archive needs zip, so only ask for it when one is being
	@# built — `make dist DIST_PLATFORMS=linux/amd64` should not want a tool it
	@# will never call.
	@case " $(DIST_PLATFORMS) " in \
		*" windows/"*) command -v zip >/dev/null 2>&1 || \
			{ echo "dist: the Windows archive needs zip"; exit 1; };; \
	esac
	@rm -rf $(DIST)
	@mkdir -p $(DIST)
	@mod="$$($(GO) list -m)"; \
	for platform in $(DIST_PLATFORMS); do \
		os="$${platform%%/*}"; label="$${platform##*/}"; arch="$$label"; goarm=""; \
		case "$$label" in armv7) arch=arm; goarm=7;; esac; \
		name="anteroom_$(VERSION)_$${os}_$${label}"; \
		bin="anteroom"; \
		case "$$os" in windows) bin="anteroom.exe";; esac; \
		echo "  $$platform"; \
		mkdir -p "$(DIST)/$$name"; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" GOARM="$$goarm" \
			$(GO) build -trimpath \
				-ldflags="-s -w \
					-X $$mod/internal/metrics.Revision=$(VCS_REF) \
					-X $$mod/internal/metrics.Version=$(VERSION)" \
				-o "$(DIST)/$$name/$$bin" ./cmd/anteroom || exit 1; \
		cp $(DIST_EXTRA) "$(DIST)/$$name/" || exit 1; \
		case "$$os" in \
			windows) (cd $(DIST) && zip -qr "$$name.zip" "$$name") || exit 1;; \
			*) tar -C $(DIST) -czf "$(DIST)/$$name.tar.gz" "$$name" || exit 1;; \
		esac; \
		rm -rf "$(DIST)/$$name"; \
	done
	@cd $(DIST) && $(SHA256) anteroom_* > SHA256SUMS
	@# One archive per platform, or the release would ship fewer assets than the
	@# docs promise. The loop above aborts on a failed build, so this catches the
	@# quieter version: a platform that produced nothing without failing.
	@built=$$(ls -1 $(DIST) | grep -c '^anteroom_'); \
	want=$$(echo $(DIST_PLATFORMS) | wc -w | tr -d ' '); \
	test "$$built" -eq "$$want" || { \
		echo "dist: built $$built archives, expected $$want"; exit 1; }
	@echo "$(DIST)/:" && ls -1 $(DIST)

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
